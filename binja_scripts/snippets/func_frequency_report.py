#
#
# Prints the most frequently called functions.  For a stripped binary or
# firmware image these are the best functions to start with because they
# will have the most impact on the readability of the code elsewhere

MAX_LEN_OF_FUNC_LIST = 20

unnamed_functions = {}
for curfunc in bv.functions:
    if curfunc.name.startswith("sub_"):
        num_xrefs = sum(1 for x in curfunc.caller_sites)
        unnamed_functions[curfunc.name] = num_xrefs
        #print(f"Unsorted, {curfunc.name} is called {len(curfunc.callees)}")

sorted_func_list = sorted(unnamed_functions.keys(), key=unnamed_functions.get)

while(len(sorted_func_list) > MAX_LEN_OF_FUNC_LIST):
    sorted_func_list.pop(0)

for sf in sorted_func_list:
    print(f"Function {sf} is called {unnamed_functions[sf]}")

