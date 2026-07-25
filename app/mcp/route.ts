import { createMcpHandler } from "mcp-handler";
import { z } from "zod";

export const runtime = "nodejs";
export const maxDuration = 60;

type Args = Record<string, unknown>;
type ToolDefinition = {
  name: string;
  description: string;
  schema: Record<string, z.ZodTypeAny>;
};

const pagination = {
  cursor: z.string().optional().describe("Cursor for pagination"),
  page_size: z.number().optional().describe("Number of lines per page"),
};
const listing = {
  filter: z.string().optional().describe("Regular expression used to filter results"),
  count: z.boolean().optional().describe("Return only the number of matching results"),
  ...pagination,
};
const address = z.string().describe("Address or radare2 expression");
const addressPage = { address, ...pagination };
const empty = {};

const tools: ToolDefinition[] = [
  { name: "open_file", description: "Opens a binary file with radare2 for analysis. Use an absolute file_path.", schema: { file_path: z.string(), baddr: z.string().optional(), arch: z.string().optional(), bits: z.string().optional(), cpu: z.string().optional() } },
  { name: "run_javascript", description: "Executes JavaScript code using radare2's qjs runtime", schema: { script: z.string() } },
  { name: "run_frida_script", description: "Executes Frida JavaScript code", schema: { script: z.string() } },
  { name: "run_command", description: "Executes a raw radare2 command directly", schema: { command: z.string(), ...pagination } },
  { name: "run_script", description: "Runs a local radare2 command script file", schema: { file_path: z.string(), ...pagination } },
  { name: "list_sessions", description: "Lists available r2agent sessions in JSON format", schema: empty },
  { name: "open_session", description: "Connects to a remote r2 instance using r2pipe API", schema: { url: z.string() } },
  { name: "close_session", description: "Close the currently open remote session", schema: empty },
  { name: "close_file", description: "Close the currently open file", schema: empty },
  { name: "list_functions", description: "Lists all functions discovered during analysis", schema: { only_named: z.boolean().optional(), filter: z.string().optional(), count: z.boolean().optional(), start: z.number().optional(), max_length: z.number().optional() } },
  { name: "list_functions_tree", description: "Lists functions and successors (aflmu)", schema: listing },
  { name: "list_libraries", description: "Lists all shared libraries linked to the binary", schema: listing },
  { name: "list_imports", description: "Lists imported symbols", schema: listing },
  { name: "list_exports", description: "Lists exported symbols from the binary or process", schema: listing },
  { name: "list_sections", description: "Displays memory sections and segments from the binary", schema: listing },
  { name: "list_memory_maps", description: "Lists memory regions of the process with addresses and permissions", schema: listing },
  { name: "show_function_details", description: "Displays detailed information about the current function", schema: empty },
  { name: "get_current_address", description: "Shows the current position and function name", schema: empty },
  { name: "show_info", description: "Displays information about the binary or target process", schema: empty },
  { name: "list_symbols", description: "Shows all symbols with addresses", schema: listing },
  { name: "list_entrypoints", description: "Displays program entrypoints, constructors and main function", schema: empty },
  { name: "list_methods", description: "Lists all methods belonging to the specified class", schema: { classname: z.string(), ...listing } },
  { name: "list_classes", description: "Lists class names from C++, Objective-C, Swift, Java and Dalvik", schema: listing },
  { name: "list_decompilers", description: "Shows all available decompiler backends", schema: empty },
  { name: "rename_function", description: "Renames the function at the specified address", schema: { name: z.string(), address } },
  { name: "rename_flag", description: "Renames a local variable or data reference", schema: { address, name: z.string(), new_name: z.string() } },
  { name: "use_decompiler", description: "Selects which decompiler backend to use", schema: { name: z.string() } },
  { name: "get_function_prototype", description: "Retrieves the function signature at the specified address", schema: { address } },
  { name: "set_function_prototype", description: "Sets the function signature", schema: { address, prototype: z.string() } },
  { name: "set_comment", description: "Adds a comment at the specified address", schema: { address, message: z.string() } },
  { name: "list_strings", description: "Lists strings from data sections with optional regex filter", schema: listing },
  { name: "list_all_strings", description: "Scans the entire binary for strings with optional regex filter", schema: listing },
  { name: "analyze", description: "Runs binary analysis with optional depth level", schema: { level: z.number().optional(), timeout_seconds: z.number().optional() } },
  { name: "xrefs_to", description: "Finds all code references to the specified address", schema: { address } },
  { name: "decompile_function", description: "Shows C-like pseudocode of the function at an address", schema: addressPage },
  { name: "list_files", description: "Lists files in the specified path using radare2", schema: { path: z.string(), ...listing } },
  { name: "disassemble_function", description: "Shows assembly listing of the function at an address", schema: addressPage },
  { name: "disassemble", description: "Disassembles instructions from an address", schema: { address, num_instructions: z.number().optional() } },
  { name: "calculate", description: "Evaluates a math expression using radare2's number parser", schema: { expression: z.string() } },
  { name: "get_pid", description: "Gets the process ID of the target process", schema: empty },
  { name: "list_threads", description: "Lists all threads in the target process", schema: listing },
  { name: "dump_registers", description: "Shows register values for target process threads", schema: { thread_id: z.number().optional() } },
  { name: "hexdump", description: "Prints memory contents in hexdump style", schema: { address, size: z.string() } },
  { name: "memory_map_here", description: "Shows memory map information at the current address", schema: empty },
  { name: "list_heap_allocations", description: "Lists malloc and heap memory ranges", schema: listing },
  { name: "alloc_memory", description: "Allocates memory in a Frida target process heap", schema: { size: z.number().optional(), string: z.string().optional() } },
  { name: "change_memory_protection", description: "Changes memory protection at an address", schema: { address, size: z.number(), protection: z.string() } },
  { name: "search", description: "Searches for strings, hex patterns, wide strings or numeric values", schema: { query: z.string(), type: z.string().optional(), value_size: z.number().optional() } },
  { name: "lookup_address", description: "Describes what is at a given address", schema: { address } },
  { name: "lookup_export", description: "Resolves an export name to its implementation address", schema: { name: z.string() } },
  { name: "lookup_symbol", description: "Resolves an address to its symbol name", schema: { address } },
];

const q = (value: unknown) => JSON.stringify(String(value ?? ""));
const at = (args: Args) => ` @ ${String(args.address ?? "$$")}`;

function commandFor(name: string, args: Args): string {
  switch (name) {
    case "open_file": return `r2 -q ${args.arch ? `-a ${q(args.arch)} ` : ""}${args.bits ? `-b ${q(args.bits)} ` : ""}${args.baddr ? `-B ${q(args.baddr)} ` : ""}${q(args.file_path)}`;
    case "close_file": return "o-*";
    case "run_command": return String(args.command);
    case "run_javascript": return `js ${q(args.script)}`;
    case "run_frida_script": return `: ${q(args.script)}`;
    case "run_script": return `. ${q(args.file_path)}`;
    case "list_sessions": return "r2agent -Lj";
    case "open_session": return `Connect r2pipe to ${String(args.url)}`;
    case "close_session": return "Close the active r2pipe session";
    case "list_functions": return "afl";
    case "list_functions_tree": return "aflmu";
    case "list_libraries": return "ilq";
    case "list_imports": return "iiq";
    case "list_exports": return "iEq";
    case "list_sections": return "iS;iSS";
    case "list_memory_maps": return "dm";
    case "show_function_details": return "afi";
    case "get_current_address": return "s;fd";
    case "show_info": return "i;iH";
    case "list_symbols": return "isq~!func.,!imp.";
    case "list_entrypoints": return "ies";
    case "list_methods": return `ic ${q(args.classname)}`;
    case "list_classes": return "icqq";
    case "list_decompilers": return "e cmd.pdc=?";
    case "rename_function": return `afn ${q(args.name)}${at(args)}`;
    case "rename_flag": return `fr ${q(args.name)} ${q(args.new_name)}${at(args)}`;
    case "use_decompiler": return `e cmd.pdc=${String(args.name)}`;
    case "get_function_prototype": return `afs${at(args)}`;
    case "set_function_prototype": return `afs ${q(args.prototype)}${at(args)}`;
    case "set_comment": return `CC ${q(args.message)}${at(args)}`;
    case "list_strings": return "izqq";
    case "list_all_strings": return "izzzqq";
    case "analyze": return ["aa", "aaa", "aaaa", "aaaaa"][Math.max(0, Math.min(4, Number(args.level ?? 2)))] ?? "aaa";
    case "xrefs_to": return `axt${at(args)}`;
    case "decompile_function": return `pdc${at(args)}`;
    case "list_files": return `ls -q ${q(args.path)}`;
    case "disassemble_function": return `pdf${at(args)}`;
    case "disassemble": return `pd ${Number(args.num_instructions ?? 10)}${at(args)}`;
    case "calculate": return `?v ${String(args.expression)}`;
    case "get_pid": return "dp";
    case "list_threads": return "dpt";
    case "dump_registers": return args.thread_id === undefined ? "dr" : `dr ${Number(args.thread_id)}`;
    case "hexdump": return `px ${String(args.size)}${at(args)}`;
    case "memory_map_here": return "dm.";
    case "list_heap_allocations": return "dmh";
    case "alloc_memory": return args.string === undefined ? `:dma ${Number(args.size ?? 0)}` : `:dmas ${q(args.string)}`;
    case "change_memory_protection": return `:dmp ${String(args.address)} ${Number(args.size)} ${String(args.protection)}`;
    case "search": return `${args.type === "hex" ? "/x" : args.type === "wide" ? "/w" : args.type === "value" ? `/v${Number(args.value_size ?? 4)}` : "/"} ${String(args.query)}`;
    case "lookup_address": return `fd${at(args)}`;
    case "lookup_export": return `iaE ${q(args.name)}`;
    case "lookup_symbol": return `is.${at(args)}`;
    default: return name;
  }
}

const capabilitiesTools = Object.fromEntries(
  tools.map((tool) => [tool.name, { description: tool.description }]),
);

const handler = createMcpHandler(
  async (server) => {
    const dynamicServer = server as any;
    for (const tool of tools) {
      dynamicServer.tool(
        tool.name,
        tool.description,
        tool.schema,
        async (args: Args = {}) => {
          const command = commandFor(tool.name, args);
          return {
            content: [{
              type: "text",
              text: `Radare2 is a native CLI and cannot execute inside this Vercel serverless function. Run this command in a local radare2 session:\n\n${command}\n\nArguments: ${JSON.stringify(args)}`,
            }],
          };
        },
      );
    }
  },
  { capabilities: { tools: capabilitiesTools } },
  { basePath: "", verboseLogs: true, maxDuration: 60, disableSse: true },
);

export { handler as GET, handler as POST, handler as DELETE };
