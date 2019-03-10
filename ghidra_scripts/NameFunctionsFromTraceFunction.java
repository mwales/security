/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// Given a routine, show all the calls to that routine and their parameters.
//    Place the cursor on a function (can be an external .dll function).
//    Execute the script.
//    The decompiler will be run on everything that calls the function at the cursor
//    All calls to the function will display with their parameters to the function.
//
//   This script assumes good flow, that switch stmts are good.
//
//@category Functions

import java.util.Iterator;
import java.util.Vector;
import java.util.HashMap;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;

import docking.widgets.dialogs.NumberInputDialog;
import docking.widgets.table.ChooseColumnsDialog;

import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SourceType;

public class NameFunctionsFromTraceFunction extends GhidraScript {

	private Address lastAddr = null;

	public class RenameFunctionData 
	{
		Address functionAddressToRename;
		String functionOldName;
		Address functionNewNameAddress;
		String functionNewName;
	}

	Vector<RenameFunctionData> renameDataOld;
	
	HashMap<Function,String> renameData;
	
	void addFunctionRenameEntry(Address functionToRename,
	                            Address functionNewNameAddress)
	{
		log("Registering func @ " + functionToRename.toString() + " to "
		    + functionNewNameAddress.toString());
	}

	private String debugToFile = "debug.txt";
	private BufferedWriter debugLog = null;

	/**
	 * Allows me to log to a file since really large files may cause log to
	 * overflow ghidra console
	 */
	private void log(String text) 
	{
		print(text + "\n");
		System.out.flush();

		if (debugToFile.isEmpty()) 
		{
			return;
		}
		try 
		{
			if (debugLog == null)
			{
				// Open the log file!
				debugLog = new BufferedWriter(new FileWriter(debugToFile));
			}

			debugLog.write(text + "\n");
			debugLog.flush();
		}
		catch (IOException e)
		{
			print(e.getMessage());
			System.out.flush();
		}

	}
	
	private int argNumberForTrace;

	@Override
	public void run() throws Exception 
	{
		
		
		
		renameData = new HashMap<Function,String>();

		if (currentLocation == null) 
		{
			log("No Location.");
			return;
		}
		


		PluginTool pluginTool = state.getTool();
		NumberInputDialog nid = new NumberInputDialog("Argument Number", 0, 0);

		pluginTool.showDialog(nid);

		if (nid.wasCancelled())
		{
			printf("User canceled");
			System.out.flush();
			return;
		}

		argNumberForTrace = nid.getValue();

		Listing listing = currentProgram.getListing();

		Function func = listing.getFunctionContaining(currentAddress);

		if (func == null) 
		{
			log("No Function at address " + currentAddress);
			return;
		}

		log("Going to argument " + argNumberForTrace + " for trace function " + func.getName());

		DecompInterface decomplib = setUpDecompiler(currentProgram);
		
		try 
		{
			if (!decomplib.openProgram(currentProgram))
			{
				log("Decompile Error: " + decomplib.getLastMessage());
				return;
			}

			// call decompiler for all refs to current function
			Symbol sym = this.getSymbolAt(func.getEntryPoint());

			Reference refs[] = sym.getReferences(null);

			for (int i = 0; (i < refs.length) /* && (i<3) */; i++) 
			{
				if (monitor.isCancelled())
				{
					break;
				}

				// get function containing.
				Address refAddr = refs[i].getFromAddress();
				Function refFunc = currentProgram.getFunctionManager()
						.getFunctionContaining(refAddr);

				if (refFunc == null) 
				{
					continue;
				}

				// decompile function
				// look for call to this function
				// display call
				analyzeFunction(decomplib, currentProgram, refFunc, refAddr);
			}
		}
		finally 
		{
			decomplib.dispose();
		}
		
		String displayList = "Should we rename the following functions?\n\n";
		int numItemsDisplayed = 0;
		for(HashMap.Entry<Function,String> it : renameData.entrySet())
		{
			displayList += it.getKey().getName();
			displayList += " => ";
			displayList += it.getValue();
			displayList += "\n";
			
			numItemsDisplayed++;
			if (numItemsDisplayed == 30)
			{
				displayList += "(plus ";
				displayList += renameData.size() - 30;
				displayList += " more) ...";
				break;
			}
		}
		
		if (!askYesNo("Rename Functions?", displayList))
		{
			// User selected no
			return;
		}
		
		// Rename all the functions!
		for(HashMap.Entry<Function,String> it : renameData.entrySet())
		{
			log("Renaming " + it.getKey() + " to " + it.getValue());
			
			Function f = it.getKey();
			f.setName(it.getValue(), SourceType.USER_DEFINED);
		}

		lastAddr = null;
	}

	private DecompInterface setUpDecompiler(Program program)
	{
		DecompInterface decomplib = new DecompInterface();
        
		DecompileOptions options;
		options = new DecompileOptions(); 
		OptionsService service = state.getTool().getService(OptionsService.class);
		if (service != null) 
		{
			ToolOptions opt = service.getOptions("Decompiler");
			options.grabFromToolAndProgram(null,opt,program);    	
		}
		
        decomplib.setOptions(options);
        
		decomplib.toggleCCode(true);
		decomplib.toggleSyntaxTree(true);
		decomplib.setSimplificationStyle("decompile");
		
		return decomplib;
	}

	/**
	 * Analyze a functions references
	 */
	public void analyzeFunction(DecompInterface decomplib, Program prog, Function f, Address refAddr) 
	{

		if (f == null)
		{
			return;
		}

		// don't decompile the function again if it was the same as the last one
		//
		if (!f.getEntryPoint().equals(lastAddr))
		{
			decompileFunction(f, decomplib);
		}
		
		lastAddr = f.getEntryPoint();

		Instruction instr = prog.getListing().getInstructionAt(refAddr);
		if (instr == null) 
		{
			return;
		}

		log(printCall(f, refAddr));
	}

	HighFunction hfunction = null;

	ClangTokenGroup docroot = null;

	public boolean decompileFunction(Function f, DecompInterface decomplib)
	{
		// decomplib.setSimplificationStyle("normalize", null);
		// HighFunction hfunction = decomplib.decompileFunction(f);

		DecompileResults decompRes = decomplib.decompileFunction(f, decomplib.getOptions().getDefaultTimeout(), monitor);
		//String statusMsg = decomplib.getDecompileMessage();

		hfunction = decompRes.getHighFunction();
		docroot = decompRes.getCCodeMarkup();
		
		for(int i = 0; i < docroot.numChildren(); i++)
		{
			log("Child " + i + ": " + docroot.Child(i).toString());
		}

		if (hfunction == null)
		{
			return false;
		}

		return true;
	}

	/**
	 * get the pcode ops that refer to an address
	 */
	public Iterator<PcodeOpAST> getPcodeOps(Address refAddr)
	{
		if (hfunction == null)
		{
			return null;
		}
		
		Iterator<PcodeOpAST> piter = hfunction.getPcodeOps(refAddr.getPhysicalAddress());
		return piter;
	}

	/**
	 * Prints the call at refAddr in the function f
	 **/
	public String printCall(Function f, Address refAddr)
	{
		log("function = " + f.getName());
		
		StringBuffer buff = new StringBuffer();

		printCall(f, refAddr, docroot, buff, false, false);

		return buff.toString();
	}

	private boolean printCall(Function f, Address refAddr, ClangNode node, StringBuffer buff, boolean didStart, boolean isCall) 
	{
		if (node == null)
		{
			return false;
		}
		
		Address min = node.getMinAddress();
		Address max = node.getMaxAddress();
		if (min == null)
		{
			return false;
		}

		if (refAddr.getPhysicalAddress().equals(max) && node instanceof ClangStatement)
		{
			ClangStatement stmt = (ClangStatement) node;
			// Don't check for an actual call. The call could be buried more deeply.  As long as the original call reference site
			// is the max address, then display the results.
			// So this block assumes that the last address contained in the call will be the
			// address you are looking for.
			//    - This could lead to strange behavior if the call reference is placed on some address
			//    that is not the final call point used by the decompiler.
			//    - Also if there is a delay slot, then the last address for the call reference point
			//    might not be the last address for the block of PCode.
			//if (stmt.getPcodeOp().getOpcode() == PcodeOp.CALL) {
			if (!didStart) 
			{
				Address nodeAddr = node.getMaxAddress();
				// Decompiler only knows base space.
				//   If reference came from an overlay space, convert address back
				if (refAddr.getAddressSpace().isOverlaySpace()) 
				{
					nodeAddr = refAddr.getAddressSpace().getOverlayAddress(nodeAddr);
				}
				buff.append(" " + nodeAddr + "   : ");
			}
				
				if (!functionCallArgAnalysis(f, refAddr, stmt))
				{
					buff.append("   " + toString(stmt));
				}
				return true;
			//}
		}
		
		for (int j = 0; j < node.numChildren(); j++)
		{
			isCall = node instanceof ClangStatement;
			didStart |= printCall(f, refAddr, node.Child(j), buff, didStart, isCall);
		}
		
		return didStart;
	}
	
	/**
	 * Analyze the args for the ClangStatement function.  Find the
	 * function name token first, then keep count of ClangVariableToken
	 * we are on as we iterate though the children.
	 */
	public boolean functionCallArgAnalysis(Function f, Address refAddr, ClangStatement node)
	{
		int currentArgNumber = 0;
		boolean foundFunctionNameToken = false;
		for(int i = 0; i < node.numChildren(); i++)
		{
			ClangNode subNode = node.Child(i);
			
			if (subNode instanceof ClangFuncNameToken)
			{
				// We found the function name, now we start counting the
				// arguments!
				foundFunctionNameToken = true;
			}
			
			if (!foundFunctionNameToken)
			{
				// Don't count anything before the function name
				continue;
			}
			
			if (subNode instanceof ClangVariableToken)
			{
				if (currentArgNumber < argNumberForTrace)
				{
					// Haven't hit the trace arg yet, keep iterating
					currentArgNumber++;
					continue;
				}
				
				// If we got this far, this is our trace arg!  Strip off
				// the leading and trailing quotes if present
				String funcTraceName = subNode.toString();
				if (funcTraceName.startsWith("\""))
				{
					funcTraceName = funcTraceName.substring(1);
				}
				if (funcTraceName.endsWith("\""))
				{
					int len = funcTraceName.length() - 1;
					funcTraceName = funcTraceName.substring(0, len);
				}
				
				log("At " + refAddr + " we found trace statement.  Function " +
				    f.getName() + " => " + funcTraceName);
				    
				if (f.getName().equals(funcTraceName))
				{
					log("Function already has the name " + f.getName());
					return true;
				}
				
				renameData.put(f, funcTraceName);
				log("Map has " + renameData.size() + " entries");
				    
				return true;
			}
		}
		
		// If we got here, we parsed all the subnodes, but didn't find
		// enough tokens
		if (foundFunctionNameToken)
		{
			log("We found functionName token, but only " + currentArgNumber +
			    " args");
		}
		else
		{
			log("We never even found the functionName token, WTF");
		}
		
		return false;
	}

	public String toString(ClangStatement node)
	{
		log("ClangStatementNode [" + node.getPcodeOp().getNumInputs() + 
		    "] = " + node.getPcodeOp().toString() + ", num children = " +
		    node.numChildren());
		
		StringBuffer buffer = new StringBuffer();
		int open=-1;
		for (int j = 0; j < node.numChildren(); j++)
		{
			ClangNode subNode = node.Child(j);
			if (subNode instanceof ClangSyntaxToken)
			{
				ClangSyntaxToken syntaxNode = (ClangSyntaxToken) subNode;
				if (syntaxNode.getOpen() != -1)
				{
					if (node.Child(j+2) instanceof ClangTypeToken)
					{
						open = syntaxNode.getOpen();
						continue;
					}
				}
				if (syntaxNode.getClose() == open && open != -1)
				{
					open = -1;
					continue;
				}
			}
			if (open != -1)
			{
				continue;
			}
			buffer.append(subNode.toString());
			
			log("  Node " + j + " (" + subNode.getClass().getName() + 
			    ") = " + subNode.toString());
		}
		return buffer.toString();
	}
}

