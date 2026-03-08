import json
import re 
import os

homePath = os.getcwd() ## /VRUNY/
LineListPath = homePath + "/output/LineList.json"
VulFuncPath = homePath + "/data/VulFuncs/"
PatFuncPath = homePath + "/data/PatFuncs/"
#=# Output
LineNumListPath = homePath + "/output/LineNumList.json"


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

def LineFiltering1(string):
    pattern = removeComment(string)
    pattern = normalize(pattern)
    if len(pattern) == 0:
        return pattern
    
    if pattern[0] == "+" or pattern[0] == "-":
        pattern = pattern[1:]
    
    pattern = re.sub(r'^(\/\*|\/\/|\*\/).*', "", pattern) # remove /*, //, */
    if (len(pattern) != 0) and (pattern[0] == "*") and ("=" not in pattern):
        pattern = re.sub(r'^(\*).*', "", pattern)
        
    return pattern

def LineFiltering2(string):
    pattern = removeComment(string)
    pattern = normalize(pattern)
    if len(pattern) == 0:
        return pattern
    
    pattern = re.sub(r'^(\/\*|\/\/|\*\/).*', "", pattern) # remove /*, //, */
    if (len(pattern) != 0) and (pattern[0] == "*") and ("=" not in pattern):
        pattern = re.sub(r'^(\*).*', "", pattern)
        
    return pattern


def ExtractLineNum(FuncData, TargetLine, BeforeLine, AfterLine, LineIDX):     
    f_TargetLine = LineFiltering1(TargetLine)
    if len(f_TargetLine) == 0:
        return None, None

    f_BeforeLine = LineFiltering1(BeforeLine)
    f_AfterLine = LineFiltering1(AfterLine)
        
    LineDict = {}
    Lines = FuncData.split('\n')
    for LineNum, Line in enumerate(Lines, start=1):
        LineDict[LineNum] = Line.strip()
        
    for IDX in range(LineIDX, len(LineDict)):
        CompareTargetLine = LineFiltering2(LineDict[IDX])
        if (IDX == 1):
            CompareBeforeLine = ""
            CompareAfterLine = LineFiltering2(LineDict[IDX+1])
        elif (IDX == len(LineDict)):
            CompareBeforeLine = LineFiltering2(LineDict[IDX-1])
            CompareAfterLine = ""
        else:
            CompareBeforeLine = LineFiltering2(LineDict[IDX-1])
            CompareAfterLine = LineFiltering2(LineDict[IDX+1])
        
        if (CompareTargetLine == f_TargetLine) and \
            (CompareBeforeLine == f_BeforeLine) and \
                (CompareAfterLine == f_AfterLine):
                    return IDX, f_TargetLine
        
    return None, None


def CollectLineNum(LineNumList, FuncPath, Pack, FileName, DelAddLines, Flag):
    ## function data
    FuncFilePath = FuncPath + Pack + "/" + FileName
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
                            print("Error")
                            return LineNumList
    
    ## Line save
    LineIDX = 1
    for DelAddLine in DelAddLines: 
        TargetLine = DelAddLine[0]
        BeforeLine = DelAddLine[1]
        AfterLine = DelAddLine[2]
        
        ## Extract line number
        LineNum, FinalTargetLine = ExtractLineNum(FuncData, TargetLine, BeforeLine, AfterLine, LineIDX)
        if LineNum == None or FinalTargetLine == None:
            continue

        if Pack not in LineNumList:
            LineNumList[Pack] = {}
        if FileName not in LineNumList[Pack]:
            LineNumList[Pack][FileName] = {}
        if Flag not in LineNumList[Pack][FileName]:
            LineNumList[Pack][FileName][Flag] = []
        LineNumList[Pack][FileName][Flag].append(str(LineNum) + "@@" + FinalTargetLine)
        
        LineIDX = LineNum
    
    return LineNumList


def SlidingMapping(filtered_vul, filtered_pat):
    dict_vul = {}
    dict_pat = {}
    for EachVul in filtered_vul:
        EachVulNum = EachVul.split("@@")[0]
        EachVulCode = EachVul.split("@@")[1]
        dict_vul[EachVulCode] = EachVulNum
    for EachPat in filtered_pat:
        EachPatNum = EachPat.split("@@")[0]
        EachPatCode = EachPat.split("@@")[1]
        dict_pat[EachPatCode] = EachPatNum
    
    
    map_vul = []
    map_pat = []
    for EachVulCode, EachVulNum in dict_vul.items():
        for EachPatCode, EachPatNum in dict_pat.items():
            if len(EachVulCode) > len(EachPatCode):
                for i in range(len(EachVulCode) - len(EachPatCode) + 1):
                    if (EachVulCode[i:i + len(EachPatCode)].lower() == EachPatCode.lower()):
                        map_vul.append(EachVulNum+"@@"+EachVulCode)
                        map_pat.append(EachPatNum+"@@"+EachPatCode)
                        break

            if len(EachVulCode) < len(EachPatCode):
                for i in range(len(EachPatCode) - len(EachVulCode) + 1):
                    if (EachPatCode[i:i + len(EachVulCode)].lower() == EachVulCode.lower()):
                        map_vul.append(EachVulNum+"@@"+EachVulCode)
                        map_pat.append(EachPatNum+"@@"+EachPatCode)
                        break

            if len(EachVulCode) == len(EachPatCode):                
                if (EachVulCode.lower() == EachPatCode.lower()):
                    map_vul.append(EachVulNum+"@@"+EachVulCode)
                    map_pat.append(EachPatNum+"@@"+EachPatCode)

    f_filtered_vul = list(set(filtered_vul)-set(map_vul))
    f_filtered_pat = list(set(filtered_pat)-set(map_pat))

    return f_filtered_vul, f_filtered_pat


def SaveResult(LineNumListPath, LineNumList):
    with open(LineNumListPath, "w") as f:
        json.dump(LineNumList, f, indent = 4)
    f.close()
    

def main():
    f1 = open(LineListPath, 'r')
    LineList = json.load(f1)
    
    LineNumList = {}
    FinalLineNumList = {}
    for Pack in LineList:
        for FileName in LineList[Pack]:
            if "Vul" in LineList[Pack][FileName]:
                LineNumList = CollectLineNum(LineNumList, VulFuncPath, Pack, FileName, LineList[Pack][FileName]["Vul"], "Vul")
            if "Pat" in LineList[Pack][FileName]:
                LineNumList = CollectLineNum(LineNumList, PatFuncPath, Pack, FileName, LineList[Pack][FileName]["Pat"], "Pat")                
            
            ## Classifying case 
            if Pack not in FinalLineNumList:
                FinalLineNumList[Pack] = {}
            if FileName not in FinalLineNumList[Pack]:
                FinalLineNumList[Pack][FileName] = {}
            
            try: 
                if ("Pat" in LineNumList[Pack][FileName]) and ("Vul" in LineNumList[Pack][FileName]):
                    vul_list = LineNumList[Pack][FileName]["Vul"]
                    pat_list = LineNumList[Pack][FileName]["Pat"]
                    
                    pat_code_set = set(p.split('@@', 1)[1] for p in pat_list)
                    vul_code_set = set(p.split('@@', 1)[1] for p in vul_list)
                    
                    filtered_vul = [v for v in vul_list if v.split('@@', 1)[1] not in pat_code_set]
                    filtered_pat = [v for v in pat_list if v.split('@@', 1)[1] not in vul_code_set]
                    
                    if len(filtered_vul) == 0 and len(filtered_pat) == 0: 
                        FinalLineNumList[Pack][FileName]["Vul"] = LineNumList[Pack][FileName]["Vul"] 
                    elif len(filtered_vul) == 0 and len(filtered_pat) != 0: 
                        FinalLineNumList[Pack][FileName]["Pat"] = filtered_pat 
                    elif len(filtered_vul) != 0 and len(filtered_pat) == 0: 
                        FinalLineNumList[Pack][FileName]["Vul"] = filtered_vul 
                    elif len(filtered_vul) != 0 and len(filtered_pat) != 0: 
                        ## Sliding
                        f_filtered_vul, f_filtered_pat = SlidingMapping(filtered_vul, filtered_pat)
                        if len(f_filtered_vul) == 0 and len(f_filtered_pat) == 0: 
                            FinalLineNumList[Pack][FileName]["Vul"] = filtered_vul 
                        elif len(f_filtered_vul) == 0 and len(f_filtered_pat) != 0:
                            FinalLineNumList[Pack][FileName]["Pat"] = f_filtered_pat 
                        elif len(f_filtered_vul) != 0 and len(f_filtered_pat) == 0:
                            FinalLineNumList[Pack][FileName]["Vul"] = f_filtered_vul 
                        elif len(f_filtered_vul) != 0 and len(f_filtered_pat) != 0:
                            FinalLineNumList[Pack][FileName]["Vul"] = f_filtered_vul 
                            FinalLineNumList[Pack][FileName]["Pat"] = f_filtered_pat 
                elif ("Pat" in LineNumList[Pack][FileName]) and ("Vul" not in LineNumList[Pack][FileName]):
                    FinalLineNumList[Pack][FileName]["Pat"] = LineNumList[Pack][FileName]["Pat"]             
                else:
                    FinalLineNumList[Pack][FileName]["Vul"] = LineNumList[Pack][FileName]["Vul"] 
            except KeyError: 
                print("KeyError: "+str(Pack)+" : "+str(FileName))
    
    SaveResult(LineNumListPath, FinalLineNumList)

if __name__ == "__main__":
	main()
