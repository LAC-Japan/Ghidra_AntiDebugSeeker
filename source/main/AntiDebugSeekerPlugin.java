package antidebugseeker;

import java.awt.BorderLayout;

import javax.swing.*;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.KeyBindingData;
import docking.action.ToolBarData;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.*;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.JFileChooser;
import javax.swing.KeyStroke;
import javax.swing.filechooser.FileNameExtensionFilter;
import resources.ResourceManager;

@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = ExamplesPluginPackage.NAME,
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "Use AntiDebugSeekerPlugin in Ghidra",
	description = "Automatically identify and extract potential anti-debugging techniques used by malware. "
)
public class AntiDebugSeekerPlugin extends ProgramPlugin {
	private Map<String, String> apiCategories = new HashMap<>();
    private Map<String, String> ruleDescriptions = new HashMap<>();
    

	MyProvider provider;

	public AntiDebugSeekerPlugin(PluginTool tool) {
		super(tool);

		provider = new MyProvider(tool, getName(), this);

		String topicName = this.getClass().getPackage().getName();
		String anchorName = "HelpAnchor";
		provider.setHelpLocation(new HelpLocation(topicName, anchorName));
	}

	@Override
	public void init() {
		super.init();
	}
	
	private static class MyProvider extends ComponentProvider {
		private JTextArea textArea;
		private JPanel panel;
		private JLabel imageLabel;
		private JProgressBar progressBar;
		private AntiDebugSeekerPlugin myPlugin;
		private DockingAction analyzeAction;

		public MyProvider(PluginTool tool, String owner, AntiDebugSeekerPlugin plugin) {
			super(plugin.getTool(), owner, owner);
			this.myPlugin = plugin;
			setIcon(ResourceManager.loadImage("images/icon.png"));
			buildPanel();
			createActions();
		}

		private void buildPanel() {
			panel = new JPanel(new BorderLayout());
			textArea = new JTextArea(5, 25);
			textArea.setEditable(false);
			panel.add(new JScrollPane(textArea), BorderLayout.CENTER);
			
			JPanel westPanel = new JPanel(new BorderLayout());
			progressBar = new JProgressBar(); 
			progressBar.setIndeterminate(false); 
			progressBar.setVisible(false);
			progressBar.setMaximum(100);
			westPanel.add(progressBar, BorderLayout.WEST);
			panel.add(westPanel, BorderLayout.EAST);
			
		    ImageIcon icon = new ImageIcon(getClass().getResource("/images/dragon_magnifying_glass.gif"));
		    imageLabel = new JLabel(icon);
		    imageLabel.setVisible(false);
		    panel.add(imageLabel, BorderLayout.WEST);
		    
		    JButton startAnalyzeButton = new JButton("Start Analyze");
		    startAnalyzeButton.addActionListener(e -> analyzeAction.actionPerformed(null));
		    
		    JButton SummaryResults = new JButton("Display only the detection results");
		    SummaryResults.addActionListener(e -> summaryresults());
		    
		    JButton detectedFunctionsListButton = new JButton("Detected Function List");
		    detectedFunctionsListButton.addActionListener(e -> detectedFunctionsList());
		    
		    JPanel buttonsPanel = new JPanel(new FlowLayout());
		    buttonsPanel.add(startAnalyzeButton);
		    buttonsPanel.add(SummaryResults);
		    buttonsPanel.add(detectedFunctionsListButton);
		    panel.add(buttonsPanel, BorderLayout.NORTH);
		    
			setVisible(true);
			
		}
		
		public void summaryresults() {
		    String content = textArea.getText();
		    String[] lines = content.split("\n");

		    StringBuilder result = new StringBuilder();
		    Pattern foundPattern = Pattern.compile(".*(found|Found|Detected).*");
		    Pattern addressPattern = Pattern.compile("^\\s*([0-9A-Fa-f]{8})");

		    boolean foundSection = false;
		    for (String line : lines) {
		        if (foundPattern.matcher(line).find() && !line.contains("not found")) {
		            
		            result.append(line).append("\n");
		            foundSection = true;
		        } else if (foundSection && addressPattern.matcher(line).find()) {
		            
		            result.append("  ").append(line.trim()).append("\n");
		        } else {
		            foundSection = false;
		        }
		    }

		    textArea.setText(result.toString());
		}
		
		public void detectedFunctionsList() {
		    String content = textArea.getText();
		    Map<String, List<String>> functionMap = new LinkedHashMap<>();

		    Pattern pattern = Pattern.compile(
		        "(.*?) API found\\.\\s*(\\b[0-9A-Fa-f]{8}\\b) in function (\\b\\w+\\b)|" +
		        "Found Single keyword Rule '(.*?)' at (\\b[0-9A-Fa-f]{8}\\b) in function (\\b\\w+\\b)|" +
		        "Keyword group (.*?) found starting at: (\\b[0-9A-Fa-f]{8}\\b).*?In function (\\b\\w+\\b)"
		    );
		    Matcher matcher = pattern.matcher(content);

		    while (matcher.find()) {
		        String functionName;
		        String apiAndAddress;

		        if (matcher.group(1) != null) {
		            
		            functionName = matcher.group(3);
		            apiAndAddress = matcher.group(1) + " : " + matcher.group(2);
		        } else if (matcher.group(4) != null) {
		            functionName = matcher.group(6);
		            apiAndAddress = matcher.group(4) + " : " + matcher.group(5);
		        } else {
		            
		            functionName = matcher.group(9);
		            apiAndAddress = matcher.group(7) + " : " + matcher.group(8);
		        }

		        functionMap.putIfAbsent(functionName, new ArrayList<>());
		        functionMap.get(functionName).add(apiAndAddress);
		    }

		    StringBuilder sb = new StringBuilder();
		    functionMap.forEach((funcName, details) -> {
		        sb.append(funcName).append("\n");
		        details.forEach(detail -> sb.append("    ").append(detail).append("\n"));
		    });

		    textArea.setText(sb.toString());
		}
		
		public void appendLogMessage(String message) {
            SwingUtilities.invokeLater(() -> {
                textArea.append(message + "\n");
                textArea.setCaretPosition(textArea.getDocument().getLength());
            });
        }
		
		public void updateProgressBar(int progress) {
		    progressBar.setValue(progress);
		}

		private void createActions() {
			analyzeAction = new DockingAction("AntiDebugSeeker Start : Select Config and JSON files", getName())  {
				@Override
				public void actionPerformed(ActionContext context) {
					progressBar.setStringPainted(true);
					progressBar.setVisible(true);
					imageLabel.setVisible(true);
					
					new SwingWorker<Boolean, Void>() {
						@Override
		                protected Boolean doInBackground() throws Exception {
		                    
		                    Program currentProgram = myPlugin.getCurrentProgram();
		                    TaskMonitor monitor = TaskMonitor.DUMMY;
		                    MessageLog log = new MessageLog();
		                    return myPlugin.added(currentProgram, new AddressSet(), monitor, log);
		                }

		                @Override
		                protected void done() {
		                    try {
		                        
		                        boolean result = get();
		                        if (result) {
		                            
		                            Msg.showInfo(getClass(), panel, "Analysis Complete", "The analysis has completed successfully.\n *** Please Check the Results From Bookmarks. ***");
		                        } else {
		                            
		                            Msg.showError(this, panel, "Error", "Failed to load and analyze the selected files.");
		                        }
		                    } catch (InterruptedException | ExecutionException e) {
		                        
		                        Msg.showError(this, panel, "Error", "An error occurred during the analysis.");
		                    } finally {
		                        
		                        progressBar.setVisible(false);
		                        imageLabel.setVisible(false);
		                    }
		                }
		            }.execute();
		        }
		    };
				
			analyzeAction.setToolBarData(new ToolBarData(ResourceManager.loadImage("images/icon.png"), null));
	        analyzeAction.setEnabled(true);
	        analyzeAction.markHelpUnnecessary();
	        
	        KeyStroke keyStroke = KeyStroke.getKeyStroke(KeyEvent.VK_D, InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK);
	        analyzeAction.setKeyBindingData(new KeyBindingData(keyStroke));
	        
	        this.addLocalAction(analyzeAction);
			
		}

		@Override
		public JComponent getComponent() {
			return panel;
		}
	}
	
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
	    {
		
		int transactionID = program.startTransaction("Adding Comments and Bookmarks");

	    String configFilePath = chooseFile("Select Config File", "Config Files", "config");
		String jsonFilePath = chooseFile("Select JSON File", "JSON Files", "json");
		
		if (configFilePath == null || jsonFilePath == null) {
            log.appendMsg("File selection cancelled by user.");
            return false;
        }
		
		try {
			String jsonContent = loadJsonFileAsString(jsonFilePath);
			ruleDescriptions = parseJsonStringToMap(jsonContent);
			
			loadConfig(configFilePath, program, monitor, log);
			
			provider.appendLogMessage("AntiDebugSeeker Process Finished");
			provider.appendLogMessage("*** Please Check the Results From Bookmarks. ***");
			program.endTransaction(transactionID, true);
			return true;
		} catch (Exception e) {
			program.endTransaction(transactionID, false);
			log.appendMsg("Failed to load JSON content: " + e.getMessage());
			// Return false to indicate failure
			StringWriter sw = new StringWriter();
		    PrintWriter pw = new PrintWriter(sw);
		    e.printStackTrace(pw);
		    String stackTraceString = sw.toString();
	        log.appendMsg("Stack Trace: " + stackTraceString);
			
			return false;
		}
	}
	
	private String chooseFile(String dialogTitle, String fileTypeDescription, String fileExtension) {
	    JFileChooser fileChooser = new JFileChooser();
	    fileChooser.setDialogTitle(dialogTitle);
	    fileChooser.setAcceptAllFileFilterUsed(false);
	    fileChooser.addChoosableFileFilter(new FileNameExtensionFilter(fileTypeDescription, fileExtension));

	    int result = fileChooser.showOpenDialog(null);
	    if (result == JFileChooser.APPROVE_OPTION) {
	        return fileChooser.getSelectedFile().getAbsolutePath();
	    }
	    return null;
	}
	
	private void loadConfig(String filePath, Program program, TaskMonitor monitor, MessageLog log) throws Exception {
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
                findAndPrintApiCalls(api, program, log);
            }
            searchProgramText(keywordGroups, program, monitor, log);
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
		return contentBuilder.toString();
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
    
    private void setBackgroundColor(ColorizingService colorizingService, Address address, Color color, MessageLog log) {
        if(colorizingService != null) {
        	log.appendMsg("Cannot find ColorizingService service.");
            colorizingService.setBackgroundColor(address, address, color);
        }
    }

    private void findAndPrintApiCalls(String api, Program program, MessageLog log) throws Exception {
        
        SymbolTable symbolTable = program.getSymbolTable();
        SymbolIterator symbols = symbolTable.getSymbolIterator(api, true);
        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            if (symbol.getSymbolType() == SymbolType.FUNCTION || symbol.getSymbolType() == SymbolType.LABEL) {
                Address symbolAddress = symbol.getAddress();
                printReferences(symbolAddress, api, symbol.getSymbolType() == SymbolType.FUNCTION ? "API" : "Pointer", program ,log);
                
                String category = apiCategories.get(api);
                if (category != null && !category.isEmpty()) {
                    setComment(symbolAddress, category, program);
                }
            }
        }
    }
    
    private void setComment(Address address, String comment, Program program) {
        Listing listing = program.getListing();
        CodeUnit cu = listing.getCodeUnitAt(address);
        if (cu != null) {
            cu.setComment(CodeUnit.PRE_COMMENT, comment);
        } 
    }
    
    private void addPostComment(Address address, String comment, Program program) {
        
        CodeUnit cu = program.getListing().getCodeUnitAt(address);
        if (cu != null) {
            cu.setComment(CodeUnit.POST_COMMENT, comment);
        }
    }
    
    private void addBookmark(Address addr, String category, String comment, Program program) {
        BookmarkManager bookmarkManager = program.getBookmarkManager();
        bookmarkManager.setBookmark(addr, BookmarkType.ANALYSIS, category, comment);
    }
    
    private String findFunctionNameByAddress(Program program, Address address) {
        FunctionManager functionManager = program.getFunctionManager();
        Function function = functionManager.getFunctionContaining(address);
        return function != null ? function.getName() : "Unknown_Function";
    }
    
    private void printReferences(Address symbolAddress, String apiName, String type, Program program, MessageLog log) {
    	ColorizingService colorizingService = this.tool.getService(ColorizingService.class);
        ReferenceManager refManager = program.getReferenceManager();
        ReferenceIterator references = refManager.getReferencesTo(symbolAddress);
        boolean found = false;
        while (references.hasNext()) {
            Reference ref = references.next();
            if (ref.getReferenceType().isCall() || ref.getReferenceType().isJump()) {
                if (!found) {
                	provider.appendLogMessage(apiName + " " + type + " found.");
                    found = true;
                }
                Address refAddress = ref.getFromAddress();
                String functionName = findFunctionNameByAddress(program, refAddress);
                provider.appendLogMessage("  " + refAddress + " in function " + functionName);
                
                String category = apiCategories.get(apiName);
                if (category != null && !category.isEmpty()) {
                    setComment(refAddress, category, program);
                }
                addBookmark(refAddress, "Potential of Anti Debug API",  category + " : " + apiName, program);
                setBackgroundColor(colorizingService, refAddress, new Color(173, 255, 47), log); 
            }
        }
        if (!found) {
        	provider.appendLogMessage(apiName + " " + type + " not found.");
        }
    }

    private void searchProgramText(LinkedHashMap<String, RuleData> keywordGroups, Program program, TaskMonitor monitor, MessageLog log) throws Exception {
        Memory memory = program.getMemory();
        Listing listing = program.getListing();
        CodeUnitIterator codeUnits = listing.getCodeUnits(memory, true);
        
        int totalKeys = keywordGroups.size();
        
        int currentIndex = 0;
        for (Map.Entry<String, RuleData> entry : keywordGroups.entrySet()) {
            String ruleName = entry.getKey();
            RuleData ruleData = entry.getValue();
            
            currentIndex++;
            double progressPercentage = ((double) currentIndex / totalKeys) * 100;
            
            final int progress = (int) progressPercentage;
            SwingUtilities.invokeLater(() -> provider.updateProgressBar(progress));
            
            if (ruleData.keywords.size() == 1) {
                searchForSingleKeyword(ruleName, ruleData.keywords.get(0), codeUnits, monitor, log, program);
            } else {
                searchForMultipleKeywords(ruleName, ruleData, codeUnits, monitor, log, program);
            }
            codeUnits = listing.getCodeUnits(memory, true);
        }
    }
    
    private boolean isKeywordFound(CodeUnit cu, String keyword, Program program) {
        
        if (searchInInstructions(cu, keyword, program)) {
            return true;
        }
        return (searchInLabels(cu.getAddress(), keyword, program));
    }

    private void searchForSingleKeyword(String ruleName, String keyword, CodeUnitIterator codeUnits, TaskMonitor monitor, MessageLog log, Program program) throws Exception {
       ColorizingService colorizingService = this.tool.getService(ColorizingService.class);
       provider.appendLogMessage("Searching for " + ruleName + "...");
       while (codeUnits.hasNext() && !monitor.isCancelled()) {
           String description = ruleDescriptions.get(ruleName);
           CodeUnit cu = codeUnits.next();
           if (isKeywordFound(cu, keyword, program)) { 
               setComment(cu.getAddress(), ruleName, program);
               String functionName = findFunctionNameByAddress(program, cu.getAddress());
               provider.appendLogMessage("Found Single keyword Rule '" + ruleName + " " + keyword + "' at " + cu.getAddress() + " in function " + functionName);
               addPostComment(cu.getAddress(), description, program);
               addBookmark(cu.getAddress(), "Anti Debug Technique", ruleName, program);
               setBackgroundColor(colorizingService, cu.getAddress(), new Color(255, 200, 120), log);
           }
       }
   }

    private void searchForMultipleKeywords(String ruleName, RuleData ruleData, CodeUnitIterator codeUnits, TaskMonitor monitor, MessageLog log, Program program) throws Exception {
    	ColorizingService colorizingService = this.tool.getService(ColorizingService.class);
    	provider.appendLogMessage("Searching for keyword group: " + ruleName + " with search range: " + ruleData.searchRange + "...");
        String firstKeyword = ruleData.keywords.get(0);
        String secondKeyword = (ruleData.keywords.size() > 1) ? ruleData.keywords.get(1) : null;
        String thirdKeyword = (ruleData.keywords.size() > 2) ? ruleData.keywords.get(2) : null;

        while (codeUnits.hasNext() && !monitor.isCancelled()) {
            CodeUnit cu = codeUnits.next();
            if (isKeywordFound(cu, firstKeyword, program)) {
                Address startAddress = cu.getAddress();
                boolean directSearchSuccess = false;

                if (secondKeyword != null && SearchKeywordWithinRange(startAddress, secondKeyword, ruleData.searchRange, program)) {
                    Address SecondKeywordAddress = Where_is_Keyword(startAddress, secondKeyword, ruleData.searchRange, program);

                    if (thirdKeyword == null || SearchKeywordWithinRange(SecondKeywordAddress, thirdKeyword, ruleData.searchRange, program)) {
                    	String functionName = findFunctionNameByAddress(program, startAddress);
                    	provider.appendLogMessage("Keyword group " + ruleName + " found starting at: " + startAddress + " in direct search." + " In function " + functionName);
                    	addBookmark(startAddress, "Anti Debug Technique", ruleName, program);
                    	setBackgroundColor(colorizingService, startAddress, new Color(255, 200, 120), log);
                    	addBookmark(SecondKeywordAddress, "Second Keyword", "It was detected at", program);
                    	setBackgroundColor(colorizingService, SecondKeywordAddress, new Color(255, 200, 120), log);
                    	provider.appendLogMessage("Detected Second Keyword is " + SecondKeywordAddress);
                    	
                        if (thirdKeyword != null){
                        	Address ThirdKeywordAddress = Where_is_Keyword(SecondKeywordAddress, thirdKeyword, ruleData.searchRange, program);
                        	addBookmark(ThirdKeywordAddress, "Third Keyword", "It was detected at", program);
                        	setBackgroundColor(colorizingService, ThirdKeywordAddress, new Color(255, 200, 120), log);
                        	provider.appendLogMessage("Detected Third Keyword is " + ThirdKeywordAddress);
                        }
                        
                        directSearchSuccess = true;
                        setComment(startAddress, ruleName, program);
                        String description = ruleDescriptions.get(ruleName);
                        if (description != null) {
                            addPostComment(startAddress, description, program);
                        } 
                    }
                }

                if (!directSearchSuccess || thirdKeyword != null) {
                    List<Address> xrefAddresses = printCrossReferences(startAddress, program);
                    for (Address xrefAddress : xrefAddresses) {
                        if (secondKeyword != null && SearchKeywordWithinRange(xrefAddress, secondKeyword, ruleData.searchRange, program)) {
                        	Address xref_SecondKeywordAddress = Where_is_Keyword(xrefAddress, secondKeyword, ruleData.searchRange, program);
                        	
                            if (thirdKeyword == null || SearchKeywordWithinRange(xref_SecondKeywordAddress, thirdKeyword, ruleData.searchRange, program)) {
                            	String functionName = findFunctionNameByAddress(program, startAddress);
                            	provider.appendLogMessage("Keyword group " + ruleName + " found starting at: " + startAddress + " with cross-reference from " + xrefAddress + " In function " + functionName);
                            	addBookmark(xrefAddress, "Anti Debug Technique", ruleName, program);
                            	setBackgroundColor(colorizingService, xrefAddress, new Color(255, 200, 120), log);
                            	addBookmark(xref_SecondKeywordAddress, "Second Keyword", "It was detected at", program);
                            	setBackgroundColor(colorizingService, xref_SecondKeywordAddress, new Color(255, 200, 120), log);
                            	provider.appendLogMessage(" Detected Second Keyword is " + xref_SecondKeywordAddress);
                                
                                if (thirdKeyword != null){
                                	Address xref_ThirdKeywordAddress = Where_is_Keyword(xref_SecondKeywordAddress, thirdKeyword, ruleData.searchRange, program);
                                	addBookmark(xref_ThirdKeywordAddress, "Third Keyword", "It was detected at", program);
                                	setBackgroundColor(colorizingService, xref_ThirdKeywordAddress, new Color(255, 200, 120), log);
                                	provider.appendLogMessage("Detected Third Keyword is " + xref_ThirdKeywordAddress);
                                }
                            	
                                setComment(xrefAddress, ruleName, program);
                                
                                String description = ruleDescriptions.get(ruleName);
                                if (description != null) {
                                    addPostComment(startAddress, description, program);
                                } 
                            }
                        }
                    }
                }
            }
        }
    }

    private boolean searchInInstructions(CodeUnit cu, String keyword, Program program) {
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
                        Symbol[] symbols = program.getSymbolTable().getSymbols((Address) operand);
                        for (Symbol symbol : symbols) {
                            if (symbol.getName().contains(keyword)) {
                                return true;
                            }
                        }
                    } else if (operand instanceof Scalar) {
                        
                        Scalar scalar = (Scalar) operand;
                        String scalarValue = Long.toHexString(scalar.getValue());
                        if (scalarValue.equals(keyword.replace("0x", ""))) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }
    
    private boolean searchInLabels(Address address, String keyword, Program program) {
        SymbolTable symbolTable = program.getSymbolTable();
        Symbol[] symbols = symbolTable.getSymbols(address);
        for (Symbol symbol : symbols) {
            if (symbol.getName().contains(keyword)) {
                
                printCrossReferences(address, program);
                return true;
            }
        }
        return false;
    }
    
    private List<Address> printCrossReferences(Address address, Program program) {
        List<Address> xrefAddresses = new ArrayList<>();
        ReferenceManager refManager = program.getReferenceManager();
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

    private boolean SearchKeywordWithinRange(Address startAddress, String secondKeyword, int range, Program program) throws Exception {
        Address endAddress = startAddress.add(range);
        AddressSet addressSet = new AddressSet(startAddress, endAddress);
        CodeUnitIterator codeUnits = program.getListing().getCodeUnits(addressSet, true);

        while (codeUnits.hasNext()) {
            CodeUnit cu = codeUnits.next();
            if (isKeywordFound(cu, secondKeyword, program)) {
                return true;
            }
        }
        return false;
    }
    
    private Address Where_is_Keyword(Address startAddress, String keyword, int range, Program program) throws Exception {
        Address endAddress = startAddress.add(range);
        AddressSet addressSet = new AddressSet(startAddress, endAddress);
        CodeUnitIterator codeUnits = program.getListing().getCodeUnits(addressSet, true);

        while (codeUnits.hasNext()) {
            CodeUnit cu = codeUnits.next();
            if (isKeywordFound(cu, keyword, program)) {
                return cu.getAddress();
            }
        }
        return null;
    }
}