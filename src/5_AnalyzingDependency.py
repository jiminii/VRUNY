import json
import os
import re

from collections import defaultdict, deque, Counter


homePath = os.getcwd() ## /VRUNY/
VulFuncPath = homePath + "/data/VulFuncs/"
PatFuncPath = homePath + "/data/PatFuncs/"
VulCPGPath = homePath + "/data/VulCPG/"
PatCPGPath = homePath + "/data/PatCPG/"
LineNumListPath = homePath + "/output/LineNumList.json"
#=# Output
DepPath = homePath + "/output/DepList.json"


def removeComment(string):
	# Code for removing C/C++ style comments. (Imported from ReDeBug.)
	c_regex = re.compile(
		r'(?P<comment>//.*?$|[{}]+)|(?P<multilinecomment>/\*.*?\*/)|(?P<noncomment>\'(\\.|[^\\\'])*\'|"(\\.|[^\\"])*"|.[^/\'"]*)',
		re.DOTALL | re.MULTILINE)
	return ''.join([c.group('noncomment') for c in c_regex.finditer(string) if c.group('noncomment')])

def normalize(string):
	# Code for normalizing the input string.
	# LF and TAB literals, curly braces, and spaces are removed,
	# and all characters are lowercased.
	return ''.join(string.replace('\n', '').replace('\r', '').replace('\t', '').replace('{', '').replace('}', '').split(
		' ')).lower()

def LineFiltering(string):
    pattern = removeComment(string)
    pattern = normalize(pattern)
    if len(pattern) == 0:
        return pattern
    
    return pattern


def ExtractCodeLine(FuncFilePath, value):
    CodeLine = ""
    
    try:  
        f = open(FuncFilePath + ".c", 'r', encoding = "UTF-8")
        FuncData = ''.join(f.readlines())
    except:
        try:
            f = open(FuncFilePath + ".cpp", 'r', encoding = "UTF-8")
            FuncData = ''.join(f.readlines())
        except:
            try:
                f = open(FuncFilePath + ".cc", 'r', encoding = "UTF-8")
                FuncData = ''.join(f.readlines())
            except:
                try:  
                    f = open(FuncFilePath + ".c", 'r', encoding = "ISO-8859-1")
                    FuncData = ''.join(f.readlines())
                except:
                    try:
                        f = open(FuncFilePath + ".cpp", 'r', encoding = "ISO-8859-1")
                        FuncData = ''.join(f.readlines())
                    except:
                        try:
                            f = open(FuncFilePath + ".cc", 'r', encoding = "ISO-8859-1")
                            FuncData = ''.join(f.readlines())
                        except:
                            return CodeLine
    
    line_dict = {}
    lines = FuncData.split('\n')
    for line_num, line in enumerate(lines, start=1):
        line_dict[str(line_num)] = line.strip()

    try: 
        CodeLine = line_dict[value]
    except KeyError:
        CodeLine = ""
                                
    return CodeLine


def ExtractNumList(CPGFileLine, CPGFlag, TargetLine, CPGNumList, Flag):
    if ' -> ' in CPGFileLine and f'[ label = "{CPGFlag}:' in CPGFileLine:
        preNum = CPGFileLine.split('" -> "')[0].split('"')[1]
        postNum = CPGFileLine.split('" -> "')[1].split('"  [ ')[0]
        pair = [preNum, postNum]
        if TargetLine in pair:
            if Flag == "VAL":
                CPGNumList.extend([pair_value for pair_value in pair if pair_value != TargetLine])
            if Flag == "Path":
                CPGNumList.append(pair)
            
    return CPGNumList


def ExtractValue(CPGLine, CPGNumList, IDSIdValueList, FuncFilePath, Flag):
    if Flag == "VAL":
        for CPGNum in CPGNumList:
            for key, value in IDSIdValueList.items():
                if CPGNum == key:
                    if value in CPGLine:
                        continue
                    
                    CodeLine = ExtractCodeLine(FuncFilePath, value)
                    pattern = LineFiltering(CodeLine)
                    if len(pattern) <= 15 and "if(" not in pattern and "free" not in pattern and "Free" not in pattern: ## length size is 15 or fewer
                        continue
                    if (value+"@@"+pattern) not in CPGLine:
                        CPGLine.append(value+"@@"+pattern)
    
    if Flag == "Path":
        for CPGNum in CPGNumList:
            PreNum = CPGNum[0]
            PostNum = CPGNum[1]
            
            Pair = []
            try: 
                CodeLine = ExtractCodeLine(FuncFilePath, IDSIdValueList[PreNum])
                pattern = LineFiltering(CodeLine)
                if len(pattern) <= 15 and "if(" not in pattern and "free" not in pattern and "Free" not in pattern: ## length size is 15 or fewer
                    continue
                Pair.append(IDSIdValueList[PreNum]+"@@"+pattern)
            except KeyError:
                Pair.append("")

            try: 
                CodeLine = ExtractCodeLine(FuncFilePath, IDSIdValueList[PostNum])
                pattern = LineFiltering(CodeLine)
                if len(pattern) <= 15 and "if(" not in pattern and "free" not in pattern and "Free" not in pattern: ## length size is 15 or fewer
                    continue
                Pair.append(IDSIdValueList[PostNum]+"@@"+pattern)
            except KeyError:
                Pair.append("")
                        
            CPGLine.append(Pair)
                    
    return CPGLine    


def ExtractFuncCall(CPGPath, FuncPath, Pack, FileName):
    FuncCallList = []
    IDXFilePath = CPGPath + Pack + "/" + FileName + "_ids.txt"
    FuncFilePath = FuncPath + Pack + "/" + FileName
    
    ## 1) extract id by searching value in ids file
    IDSIdValueList = {}
    with open(IDXFilePath, 'r') as fp:
        IDXFileLines = ''.join(fp.readlines()) 
        for IDXCall in IDXFileLines.split('Call(')[1:]:
            id = None 
            methodFullName = None 
            value = None 
            for IDXCallLine in IDXCall.split('\n'):
                if 'id = ' in IDXCallLine:
                    id = IDXCallLine.split('id = ')[1].split('L,')[0]
                    
                try: 
                    if 'methodFullName = ' in IDXCallLine:
                        methodFullName = IDXCallLine.split('methodFullName = ')[1]
                    if 'lineNumber = ' in IDXCallLine: 
                        value = IDXCallLine.split('lineNumber = Some(value = ')[1].split('),')[0]
                except Exception as e:
                    print(str(IDXFilePath) + " : " + str(e))
            
            if id == None or methodFullName == None or value == None:
                continue
            if id not in IDSIdValueList:
                IDSIdValueList[id] = {}
            IDSIdValueList[id]["methodFullName"] = methodFullName
            IDSIdValueList[id]["value"] = value
            
    
    for key, data in IDSIdValueList.items():
        methodFullName = data["methodFullName"]
        value = data["value"]
        if '"<operator>.' not in methodFullName:         
            CodeLine = ExtractCodeLine(FuncFilePath, value)
            pattern = LineFiltering(CodeLine)
            if len(pattern) <= 15 and "if(" not in pattern and "free" not in pattern and "Free" not in pattern: ## length size is 15 or fewer
                continue
            if (value+"@@"+pattern) not in FuncCallList:
                FuncCallList.append(value+"@@"+pattern)
    
    return FuncCallList


def ExtractCPGLine(Lines, CPGPath, FuncPath, Pack, FileName, Flag):
    CFGLine = []
    DDGLine = []
    ASTLine = []
    CPGFilePath = CPGPath + Pack + "/" + FileName + "_cpg.txt"
    IDXFilePath = CPGPath + Pack + "/" + FileName + "_ids.txt"
    FuncFilePath = FuncPath + Pack + "/" + FileName

    for Line in Lines:
        LineNum = Line.split('@@')[0]
        LineCode = Line.split('@@')[1]
    
        ## 1) extract id by searching value in ids file
        IDSIdValueList = {}
        with open(IDXFilePath, 'r') as fp:
            IDXFileLines = ''.join(fp.readlines()) 
            for IDXCall in IDXFileLines.split('Call(')[1:]:
                id = None 
                value = None
                for IDXCallLine in IDXCall.split('\n'):
                    if 'id = ' in IDXCallLine:
                        id = IDXCallLine.split('id = ')[1].split('L,')[0]
                        
                    try: 
                        if 'lineNumber = ' in IDXCallLine: 
                            value = IDXCallLine.split('lineNumber = Some(value = ')[1].split('),')[0]
                    except Exception as e:
                        print(str(IDXFilePath) + " : " + str(e))
                
                if id == None or value == None:
                    continue
                IDSIdValueList[id] = value
           
        ## 2) search CFG, DDG in cpg file
        TargetLineList = []
        for key, value in IDSIdValueList.items():
            if LineNum == value:
                TargetLineList.append(key)
        
        CFGNumList = []  
        DDGNumList = []  
        ASTNumList = [] 
        if Flag == "VAL":
            for TargetLine in TargetLineList:
                with open(CPGFilePath, 'r') as fp:
                    CPGFileLines = ''.join(fp.readlines())
                    for CPGFileLine in CPGFileLines.split('\n'):
                        CFGNumList = ExtractNumList(CPGFileLine, "CFG", TargetLine, CFGNumList, Flag)
                        DDGNumList = ExtractNumList(CPGFileLine, "DDG", TargetLine, DDGNumList, Flag)
                        ASTNumList = ExtractNumList(CPGFileLine, "AST", TargetLine, ASTNumList, Flag)
                                
            CFGNumList = list(set(CFGNumList))
            DDGNumList = list(set(DDGNumList))
            ASTNumList = list(set(ASTNumList))
            
            ## 3) extract value by searching id in ids file 
            CFGLine = ExtractValue(CFGLine, CFGNumList, IDSIdValueList, FuncFilePath, Flag)
            DDGLine = ExtractValue(DDGLine, DDGNumList, IDSIdValueList, FuncFilePath, Flag)
            ASTLine = ExtractValue(ASTLine, ASTNumList, IDSIdValueList, FuncFilePath, Flag)
            
        if Flag == "Path":
            for TargetLine in TargetLineList:
                with open(CPGFilePath, 'r') as fp:
                    CPGFileLines = ''.join(fp.readlines())
                    for CPGFileLine in CPGFileLines.split('\n'):
                        CFGNumList = ExtractNumList(CPGFileLine, "CFG", TargetLine, CFGNumList, Flag)
                        DDGNumList = ExtractNumList(CPGFileLine, "DDG", TargetLine, DDGNumList, Flag)
                        ASTNumList = ExtractNumList(CPGFileLine, "AST", TargetLine, ASTNumList, Flag)
                                
            CFGNumList = list(map(list, set(map(tuple, CFGNumList))))
            DDGNumList = list(map(list, set(map(tuple, DDGNumList))))
            ASTNumList = list(map(list, set(map(tuple, ASTNumList))))
            
            ## 3) extract value by searching id in ids file 
            CFGLine = ExtractValue(CFGLine, CFGNumList, IDSIdValueList, FuncFilePath, Flag)
            DDGLine = ExtractValue(DDGLine, DDGNumList, IDSIdValueList, FuncFilePath, Flag)
            ASTLine = ExtractValue(ASTLine, ASTNumList, IDSIdValueList, FuncFilePath, Flag)
            
            CFGLine = list(map(list, set(map(tuple, CFGLine))))
            DDGLine = list(map(list, set(map(tuple, DDGLine))))
            ASTLine = list(map(list, set(map(tuple, ASTLine))))
        
    return CFGLine, DDGLine, ASTLine


def BuildGraph(EdgeList):
    Graph = defaultdict(list)
    for Parent, Child in EdgeList:
        Graph[Parent].append(Child)
    
    FinalGraph = defaultdict(list)
    for key, value in Graph.items():
        keyNum = int(key.split("@@")[0])
        for each in value:
            eachNum = int(each.split("@@")[0])
            if keyNum < eachNum:
                if key not in FinalGraph:
                    FinalGraph[key] = []
                FinalGraph[key].append(each)

    return FinalGraph


def FindPath_DFS(Graph, Node, Path, PathList, Visited):
    if Node in Visited:
        PathList.append(Path)
        print(f"Cycle stopped at node: {Node}, path: {Path}")
        return
    
    Path.append(Node) 
    Visited.add(Node)

    if Node not in Graph or not Graph[Node]:
        PathList.append(Path)
    else:
        for Child in Graph[Node]: 
            FindPath_DFS(Graph, Child, Path[:], PathList, Visited.copy()) 

    return PathList


def FilteringVAL(VALTargetList):
    f_VALTargetList = []
    except_list = []
    
    code_counter = Counter(item.split('@@', 1)[1] for item in VALTargetList)

    f_VALTargetList = [
        item for item in VALTargetList
        if code_counter[item.split('@@', 1)[1]] == 1
    ]
    
    except_list = [
        item for item in VALTargetList
        if code_counter[item.split('@@', 1)[1]] > 1
    ]
    
    return f_VALTargetList, except_list


def FilteringSemSlice(PathPair, except_list, f_VALTargetList):
    f_PathPair = []
    for EachPair in PathPair:
        Flag = False
        for EachLine in EachPair:
            if EachLine in except_list or EachLine not in f_VALTargetList:
                Flag = True
        
        if Flag == False:
            f_PathPair.append(EachPair)
    
    return f_PathPair


def SaveCPGLineList(CPGLineList, LineList, Pack, FileName, Flag, CPGFlag, CPGLine):
    if Pack not in CPGLineList:
        CPGLineList[Pack] = {}
    if FileName not in CPGLineList[Pack]:
        CPGLineList[Pack][FileName] = {}
    if Flag not in CPGLineList[Pack][FileName]:
        CPGLineList[Pack][FileName][Flag] = LineList[Pack][FileName][Flag]
    if CPGFlag not in CPGLineList[Pack][FileName]:
        CPGLineList[Pack][FileName][CPGFlag] = []
        
    CPGLineList[Pack][FileName][CPGFlag] = CPGLine 
    
    return CPGLineList


def Parsing(CPGLineList, LineList, Pack, FileName, Flag, CPGPath, FuncPath):
    CFGLine, DDGLine, ASTLine = ExtractCPGLine(LineList[Pack][FileName][Flag], CPGPath, FuncPath, Pack, FileName, "VAL")
    
    ## extracting Vulnerability-relevant code lines
    VALTargetList = []
    if Flag == "Vul":
        for EachLine in LineList[Pack][FileName]["Vul"]:
            LineNum = EachLine.split("@@")[0]
            LineCode = EachLine.split("@@")[1]
            if len(LineCode) <= 15 and "if(" not in LineCode and "free" not in LineCode and "Free" not in LineCode: ## length size is 15 or fewer
                continue
            VALTargetList.append(EachLine)
        VALTargetList.extend(CFGLine)
        VALTargetList.extend(DDGLine)
        VALTargetList = list(set(VALTargetList))
        if len(VALTargetList) == 0: 
            VALTargetList = LineList[Pack][FileName]["Vul"]
    if Flag == "Pat":
        VALTargetList.extend(CFGLine)
        VALTargetList.extend(DDGLine)
        VALTargetList = list(set(VALTargetList)-set(LineList[Pack][FileName]["Pat"]))
        
    f_VALTargetList, except_list = FilteringVAL(VALTargetList) 
    
    if len(CFGLine) != 0:                    
        CPGLineList = SaveCPGLineList(CPGLineList, LineList, Pack, FileName, Flag, Flag+"_CFG", CFGLine)
    if len(DDGLine) != 0:                    
        CPGLineList = SaveCPGLineList(CPGLineList, LineList, Pack, FileName, Flag, Flag+"_DDG", DDGLine)
    if len(f_VALTargetList) != 0: 
        CPGLineList = SaveCPGLineList(CPGLineList, LineList, Pack, FileName, Flag, Flag+"_VAL", f_VALTargetList)
        
    
    ## extracting Vulnerability-relevant slices
    CFGLine, DDGLine, ASTLine = ExtractCPGLine(LineList[Pack][FileName][Flag], CPGPath, FuncPath, Pack, FileName, "Path")
    
    PairTargetList = []
    PairTargetList.extend(CFGLine)
    PairTargetList.extend(DDGLine)
    PairTargetList = list(map(list, set(map(tuple, PairTargetList))))
    
    SemPath = [] 
    for Pair in PairTargetList:
        PreLine = Pair[0]
        PostLine = Pair[1]
        
        if ("" == PreLine) or ("" == PostLine) or (PreLine == PostLine):
            continue

        SemPath.append(Pair)
    SemPath = list(map(list, set(map(tuple, SemPath))))


    if len(LineList[Pack][FileName][Flag]) >= 100: 
        if Flag == "Vul":
            f_SemPath = FilteringSemSlice(SemPath, except_list, f_VALTargetList)
            CPGLineList = SaveCPGLineList(CPGLineList, LineList, Pack, FileName, Flag, Flag+"_PathPair", f_SemPath)
        if Flag == "Pat":
            PathPair = []
            for EachPath in SemPath:
                EachPair = []
                for EachLine in EachPath:
                    if EachLine not in LineList[Pack][FileName][Flag]:
                        EachPair.append(EachLine)
                if (EachPair == []) or ("" in EachPair) or (len(EachPair) == 1):
                    continue
                PathPair.append(EachPair)
            if len(PathPair) != 0: 
                f_PathPair = FilteringSemSlice(PathPair, except_list, f_VALTargetList)   
                CPGLineList = SaveCPGLineList(CPGLineList, LineList, Pack, FileName, Flag, Flag+"_PathPair", f_PathPair)
            
        return CPGLineList
        
    
    CPGGraph = BuildGraph(SemPath)
    PathPair = []
    for Root in CPGGraph:
        PathList = []
        PathList = FindPath_DFS(CPGGraph, Root, [], PathList, set())

        if Flag == "Vul":
            PathPair.extend(PathList)
        if Flag == "Pat":
            for EachPath in PathList:
                EachPair = []
                for EachLine in EachPath:
                    if EachLine not in LineList[Pack][FileName][Flag]:
                        EachPair.append(EachLine)
                if (EachPair == []) or ("" in EachPair) or (len(EachPair) == 1):
                    continue
                PathPair.append(EachPair)
        
    unique_path_pairs = list({tuple(pair) for pair in PathPair})
    PathPair = [list(pair) for pair in unique_path_pairs]
    
    if len(PathPair) != 0: 
        f_PathPair = FilteringSemSlice(PathPair, except_list, f_VALTargetList) 
        CPGLineList = SaveCPGLineList(CPGLineList, LineList, Pack, FileName, Flag, Flag+"_PathPair", f_PathPair)

    return CPGLineList


def SaveResult(CPGLineList, DepPath):
    with open(DepPath, "w") as f:
        json.dump(CPGLineList, f, indent = 4)
    f.close()
    

def main():
    f1 = open(LineNumListPath, 'r')
    LineList = json.load(f1)
    
    CPGLineList = {}
    for Pack in LineList:
        for FileName in LineList[Pack]: 
            print("FileName: "+str(FileName))
             
            if "Pat" in LineList[Pack][FileName] and "Vul" not in LineList[Pack][FileName]:
                CPGLineList = Parsing(CPGLineList, LineList, Pack, FileName, "Pat", PatCPGPath, PatFuncPath)
            elif "Vul" in LineList[Pack][FileName]:
                CPGLineList = Parsing(CPGLineList, LineList, Pack, FileName, "Vul", VulCPGPath, VulFuncPath)
            else: 
                print("Error: "+Pack+" : "+FileName)
                continue
            
    SaveResult(CPGLineList, DepPath)

if __name__ == "__main__":
	main()