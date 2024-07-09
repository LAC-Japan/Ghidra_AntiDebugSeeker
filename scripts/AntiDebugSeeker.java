import ghidra.app.script.GhidraScript;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.mem.Memory;
import ghidra.util.exception.CancelledException;
import ghidra.program.model.address.AddressSet;
import ghidra.app.cmd.comments.SetCommentsCmd;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.StringReader;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.*;
import java.awt.Color;


public class AntiDebugSeeker extends GhidraScript {
    private Map<String, String> apiCategories = new HashMap<>();
	private Map<String, String> ruleDescriptions = new HashMap<>();

    @Override
    public void run() throws Exception {
        String configFilePath = askFile("Select the Configuration File", "Open").getAbsolutePath();
    	String jsonFilePath = askFile("Select the JSON Description File", "Open").getAbsolutePath();
    	String jsonContent = loadJsonFileAsString(jsonFilePath);
    	ruleDescriptions = parseJsonStringToMap(jsonContent);
    	
        println("Start AntiDebugSeeker Script ...");
        loadConfig(configFilePath);
        println("AntiDebugSeeker Process Finished");
        println("*** Please Check the Results from Bookmarks");
    }

    private void loadConfig(String filePath) throws Exception {
        String line;
        boolean isApiSection = false;
        boolean isKeywordSection = false;
        List<String> apis = new ArrayList<>();
        LinkedHashMap<String, RuleData> keywordGroups = new LinkedHashMap<>();
        String currentRuleName = "";
        List<String> currentKeywords = new ArrayList<>();
        int defaultSearchRange = 80; // Default value setup
        int currentSearchRange = defaultSearchRange;
        String currentCategory = ""; 

        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.startsWith("###")) {
                    
                    isApiSection = line.contains("Anti_Debug_API");
                    isKeywordSection = line.contains("Anti_Debug_Technique");
                    if (isKeywordSection) {
                        currentSearchRange = defaultSearchRange; 
                    }
                } else if (line.startsWith("default_search_range=")) {
                    
                    defaultSearchRange = Integer.parseInt(line.substring("default_search_range=".length()));
                    currentSearchRange = defaultSearchRange; 
                } else if (isApiSection) {
                    if (line.startsWith("[")) {
                        
                        currentCategory = line.substring(1, line.length() - 1);
                    } else if (!line.isEmpty()) {
                        
                        apis.add(line);
                        apiCategories.put(line, currentCategory);
                    }
                } else if (isKeywordSection) {
                    if (line.startsWith("[")) {
                        if (!currentKeywords.isEmpty()) {
                            
                            keywordGroups.put(currentRuleName, new RuleData(new ArrayList<>(currentKeywords), currentSearchRange));
                            currentKeywords.clear();
                        }
                        
                        currentRuleName = line.substring(1, line.length() - 1);
                        currentSearchRange = defaultSearchRange; 
                    } else if (line.startsWith("search_range=")) {
                        
                        currentSearchRange = Integer.parseInt(line.substring("search_range=".length()));
                    } else if (!line.isEmpty()) {
                        
                        currentKeywords.add(line);
                    }
                }
            }

            if (!currentKeywords.isEmpty()) {
                
                keywordGroups.put(currentRuleName, new RuleData(new ArrayList<>(currentKeywords), currentSearchRange));
            }

            
            for (String api : apis) {
                findAndPrintApiCalls(api);
            }
            searchProgramText(keywordGroups);
        }
    }
	
	private String loadJsonFileAsString(String filePath) throws Exception {
         StringBuilder contentBuilder = new StringBuilder();
         try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
             String line;
             while ((line = br.readLine()) != null) {
                 contentBuilder.append(line).append("\n");
             }
         }
         String content = contentBuilder.toString();
         
         return content;
     }
	
	private Map<String, String> parseJsonStringToMap(String jsonString) {
        Map<String, String> descriptions = new LinkedHashMap<>();
        jsonString = jsonString.trim();

        
        jsonString = jsonString.substring(1, jsonString.length() - 1).trim();

        Pattern pattern = Pattern.compile("\"([^\"]*)\"\\s*:\\s*\"([^\"]*)\",?");
        Matcher matcher = pattern.matcher(jsonString);

        while (matcher.find()) {
            String key = matcher.group(1).replace("\\\"", "\"");
            String value = matcher.group(2).replace("\\n", "\n").replace("\\\\", "\\").replace("\\\"", "\"");

            if (value.endsWith(".")) {
                value = value.substring(0, value.length() - 1);
            }

            descriptions.put(key, value);
        }

        return descriptions;
    }

        
    private class RuleData {
           List<String> keywords;
           int searchRange;

           RuleData(List<String> keywords, int searchRange) {
               this.keywords = keywords;
               this.searchRange = searchRange;
           }
       }

    private void findAndPrintApiCalls(String api) throws Exception {
        
        SymbolTable symbolTable = currentProgram.getSymbolTable();
        SymbolIterator symbols = symbolTable.getSymbolIterator(api, true);
        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            if (symbol.getSymbolType() == SymbolType.FUNCTION || symbol.getSymbolType() == SymbolType.LABEL) {
                Address symbolAddress = symbol.getAddress();
                printReferences(symbolAddress, api, symbol.getSymbolType() == SymbolType.FUNCTION ? "API" : "Pointer");
                
                String category = apiCategories.get(api); 
                if (category != null && !category.isEmpty()) {
                    setComment(symbolAddress, category); 
                }
            }
        }
    }
    
   private void setComment(Address address, String comment) {
        Listing listing = currentProgram.getListing();
        CodeUnit cu = listing.getCodeUnitAt(address);
        if (cu != null) {
            
            cu.setComment(CodeUnit.PRE_COMMENT, comment);
        } 
    }
    
    private void addPostComment(Address address, String comment) {
        CodeUnit cu = currentProgram.getListing().getCodeUnitAt(address);
        if (cu != null) {
            cu.setComment(CodeUnit.POST_COMMENT, comment);
        }
    }
    
    private void addBookmark(Address addr, String category, String comment) {
        BookmarkManager bookmarkManager = currentProgram.getBookmarkManager();
        bookmarkManager.setBookmark(addr, BookmarkType.ANALYSIS, category, comment);
    }
    
    private void setColorAtAddress(Address address, Color color) {
        ColorizingService colorizingService = state.getTool().getService(ColorizingService.class);
        if (colorizingService == null) {
            println("Can't find ColorizingService service");
            return;
        }

        colorizingService.setBackgroundColor(address, address, color);
    }
    
    private void printReferences(Address symbolAddress, String apiName, String type) {
        ReferenceManager refManager = currentProgram.getReferenceManager();
        ReferenceIterator references = refManager.getReferencesTo(symbolAddress);
        boolean found = false;
        while (references.hasNext()) {
            Reference ref = references.next();
            if (ref.getReferenceType().isCall() || ref.getReferenceType().isJump()) {
                if (!found) {
                    println(apiName + " " + type + " found.");
                    found = true;
                }
                Address refAddress = ref.getFromAddress();
                println("  " + refAddress);
                String category = apiCategories.get(apiName); 
                if (category != null && !category.isEmpty()) {
                    setComment(refAddress, category);
                }
                addBookmark(refAddress, "Potential of Anti Debug API",  category + " : " + apiName);
                setColorAtAddress(refAddress, new Color(173, 255, 47));
            }
        }
        if (!found) {
            println(apiName + " " + type + " not found.");
        }
    }

    private void searchProgramText(LinkedHashMap<String, RuleData> keywordGroups) throws Exception {
        Memory memory = currentProgram.getMemory();
        Listing listing = currentProgram.getListing();
        CodeUnitIterator codeUnits = listing.getCodeUnits(memory, true);

        for (Map.Entry<String, RuleData> entry : keywordGroups.entrySet()) {
            String ruleName = entry.getKey();
            RuleData ruleData = entry.getValue();
            if (ruleData.keywords.size() == 1) {
                searchForSingleKeyword(ruleName, ruleData.keywords.get(0), codeUnits);
            } else {
                searchForMultipleKeywords(ruleName, ruleData, codeUnits);
            }
            codeUnits = listing.getCodeUnits(memory, true);
        }
    }
    
    private boolean isKeywordFound(CodeUnit cu, String keyword) {
        
        if (searchInInstructions(cu, keyword)) {
            return true; 
        }
        
        return (searchInLabels(cu.getAddress(), keyword)); 
    }


    private void searchForSingleKeyword(String ruleName, String keyword, CodeUnitIterator codeUnits) throws Exception {
       println("Searching for " + ruleName + "...");
       while (codeUnits.hasNext() && !monitor.isCancelled()) {
           String description = ruleDescriptions.get(ruleName);
           CodeUnit cu = codeUnits.next();
           if (isKeywordFound(cu, keyword)) { 
               setComment(cu.getAddress(), ruleName);
               println("Found Single keyword Rule'" + keyword + "' at " + cu.getAddress());
               addPostComment(cu.getAddress(), description);
               addBookmark(cu.getAddress(), "Anti Debug Technique", ruleName);
               setColorAtAddress(cu.getAddress(), new Color(255, 200, 120));
           }
       }
   }

    private void searchForMultipleKeywords(String ruleName, RuleData ruleData, CodeUnitIterator codeUnits) throws Exception {
        println("Searching for keyword group: " + ruleName + " with search range: " + ruleData.searchRange + "...");
        String firstKeyword = ruleData.keywords.get(0);
        String secondKeyword = (ruleData.keywords.size() > 1) ? ruleData.keywords.get(1) : null;
        String thirdKeyword = (ruleData.keywords.size() > 2) ? ruleData.keywords.get(2) : null;

        while (codeUnits.hasNext() && !monitor.isCancelled()) {
            CodeUnit cu = codeUnits.next();
            if (isKeywordFound(cu, firstKeyword)) {
                Address startAddress = cu.getAddress();
                boolean directSearchSuccess = false;

                if (secondKeyword != null && SearchKeywordWithinRange(startAddress, secondKeyword, ruleData.searchRange)) {
                    Address SecondKeywordAddress = Where_is_Keyword(startAddress, secondKeyword, ruleData.searchRange);

                    if (thirdKeyword == null || SearchKeywordWithinRange(SecondKeywordAddress, thirdKeyword, ruleData.searchRange)) {
                        println("Keyword group " + ruleName + " found starting at: " + startAddress + " in direct search.");
                    	addBookmark(startAddress, "Anti Debug Technique", ruleName);
                    	setColorAtAddress(startAddress, new Color(255, 200, 120));
                    	addBookmark(SecondKeywordAddress, "Second Keyword", "It was detected at");
                    	setColorAtAddress(SecondKeywordAddress, new Color(255, 200, 120));
                        println("Detected Second Keyword is " + SecondKeywordAddress);
                    	
                        if (thirdKeyword != null){
                        	Address ThirdKeywordAddress = Where_is_Keyword(SecondKeywordAddress, thirdKeyword, ruleData.searchRange);
                        	addBookmark(ThirdKeywordAddress, "Third Keyword", "It was detected at");
                        	setColorAtAddress(ThirdKeywordAddress, new Color(255, 200, 120));
                            println("Detected Third Keyword is " + ThirdKeywordAddress);
                        }
                        
                        directSearchSuccess = true;
                        setComment(startAddress, ruleName);
                        
                        String description = ruleDescriptions.get(ruleName);
                        if (description != null) {
                            
                            addPostComment(startAddress, description);
                        } 
                    }
                }

                if (!directSearchSuccess || thirdKeyword != null) {
                    List<Address> xrefAddresses = printCrossReferences(startAddress);
                    for (Address xrefAddress : xrefAddresses) {
                        
                        if (secondKeyword != null && SearchKeywordWithinRange(xrefAddress, secondKeyword, ruleData.searchRange)) {
                        	Address xref_SecondKeywordAddress = Where_is_Keyword(xrefAddress, secondKeyword, ruleData.searchRange);
                        	
                            if (thirdKeyword == null || SearchKeywordWithinRange(xref_SecondKeywordAddress, thirdKeyword, ruleData.searchRange)) {
                                println("Keyword group " + ruleName + " found starting at: " + startAddress + " with cross-reference from " + xrefAddress);
                            	addBookmark(xrefAddress, "Anti Debug Technique", ruleName);
                            	setColorAtAddress(xrefAddress, new Color(255, 200, 120));
                            	addBookmark(xref_SecondKeywordAddress, "Second Keyword", "It was detected at");
                            	setColorAtAddress(xref_SecondKeywordAddress, new Color(255, 200, 120));
                                println(" Detected Second Keyword is " + xref_SecondKeywordAddress);
                                
                                if (thirdKeyword != null){
                                	Address xref_ThirdKeywordAddress = Where_is_Keyword(xref_SecondKeywordAddress, thirdKeyword, ruleData.searchRange);
                                	addBookmark(xref_ThirdKeywordAddress, "Third Keyword", "It was detected at");
                                	setColorAtAddress(xref_ThirdKeywordAddress, new Color(255, 200, 120));
                                    println("Detected Third Keyword is " + xref_ThirdKeywordAddress);
                                }
                            	
                                setComment(xrefAddress, ruleName);
                                
                                String description = ruleDescriptions.get(ruleName);
                                if (description != null) {
                                    addPostComment(startAddress, description);
                                } 
                            }
                        }
                    }
                }
            }
        }
    }

    private boolean searchInInstructions(CodeUnit cu, String keyword) {
        if (cu instanceof Instruction) {
            Instruction ins = (Instruction) cu;
            
            if (ins.getMnemonicString().contains(keyword)) {
                return true;
            }
            
            for (int i = 0; i < ins.getNumOperands(); i++) {
            	
            	String operandRepresentation = ins.getDefaultOperandRepresentation(i);
                if (keyword.startsWith("0x")) {
                    if (operandRepresentation.equalsIgnoreCase(keyword)) {
                        return true;
                    }
                } else {
                    if (operandRepresentation.contains(keyword)) {
                        return true;
                    }
                }
            	
                Object[] operands = ins.getOpObjects(i);
                for (Object operand : operands) {
                    
                    if (operand instanceof Address) {
                        Symbol[] symbols = currentProgram.getSymbolTable().getSymbols((Address) operand);
                        for (Symbol symbol : symbols) {
                            if (symbol.getName().contains(keyword)) {
                                return true;
                            }
                        }
                    } else if (operand instanceof Scalar) {
                        
                        Scalar scalar = (Scalar) operand;
                        String scalarValue = Long.toHexString(scalar.getValue());
                        if (scalarValue.equals(keyword.replace("0x", ""))) { // "0x"を除去して比較
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }
    
    private boolean searchInLabels(Address address, String keyword) {
        SymbolTable symbolTable = currentProgram.getSymbolTable();
        Symbol[] symbols = symbolTable.getSymbols(address);
        for (Symbol symbol : symbols) {
            if (symbol.getName().contains(keyword)) {
                printCrossReferences(address);
                return true; 
            }
        }
        return false;
    }
    
    private List<Address> printCrossReferences(Address address) {
        List<Address> xrefAddresses = new ArrayList<>();
        ReferenceManager refManager = currentProgram.getReferenceManager();
        ReferenceIterator references = refManager.getReferencesTo(address);
        boolean found = false;
        while (references.hasNext()) {
            Reference ref = references.next();
            if (!found) {
                found = true;
            }
            
            xrefAddresses.add(ref.getFromAddress());
        }
        if (!found) {
            
        }
        return xrefAddresses; 
    }

    private boolean SearchKeywordWithinRange(Address startAddress, String secondKeyword, int range) throws Exception {
        Address endAddress = startAddress.add(range);
        AddressSet addressSet = new AddressSet(startAddress, endAddress);
        CodeUnitIterator codeUnits = currentProgram.getListing().getCodeUnits(addressSet, true);

        while (codeUnits.hasNext()) {
            CodeUnit cu = codeUnits.next();
            if (isKeywordFound(cu, secondKeyword)) {
                return true;
            }
        }
        return false;
    }
    
    private Address Where_is_Keyword(Address startAddress, String keyword, int range) throws Exception {
        Address endAddress = startAddress.add(range);
        AddressSet addressSet = new AddressSet(startAddress, endAddress);
        CodeUnitIterator codeUnits = currentProgram.getListing().getCodeUnits(addressSet, true);

        while (codeUnits.hasNext()) {
            CodeUnit cu = codeUnits.next();
            if (isKeywordFound(cu, keyword)) {
                return cu.getAddress(); 
            }
        }
        return null;
    }

}
