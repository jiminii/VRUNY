import os
import subprocess
import re
import json

homePath = os.getcwd() ## /VRUNY/
DiffPath = homePath + "/data/diffs/"
ClonePath = homePath + "/data/clones/"
CtagPath = homePath + "/ctags/ctags"
#=# Output
VulFuncPath = homePath + "/data/VulFuncs/"
PatFuncPath = homePath + "/data/PatFuncs/"
OutputPath = homePath + "/output/"
LineListPath = homePath + "/output/LineList.json"


shouldMake = [VulFuncPath, PatFuncPath, OutputPath]
for eachRepo in shouldMake:
	if not os.path.isdir(eachRepo):
		os.mkdir(eachRepo)


def ExtractFunc(Pack, Diff, Command, VulPatFile, StartLine, EndLine, VulPatPath, ResultPath, DelAddLines, LineList):
    FileName = ""
    try:
        Result = subprocess.check_output(Command, stderr=subprocess.STDOUT, shell=True)
    except subprocess.CalledProcessError as e:
        print("subprocess.CalledProcessError: "+str(Pack) + " : " + str(Diff) + " : "  + str(e))
    CtagData = subprocess.check_output(CtagPath + " --fields=+ne -o - --sort=no " + VulPatFile, stderr=subprocess.STDOUT, shell=True).decode(errors="ignore")

    CtagData = str(CtagData)
    try:
        with open(VulPatFile, "r", encoding = "UTF-8") as f:
            FileData = "".join(f.readlines())
    except:
        with open(VulPatFile, "r", encoding = "ISO-8859-1") as f:
            FileData = "".join(f.readlines()) 
    try: 
        flag = 0
        for CtagLine in CtagData.split("\n"):
            if CtagLine == "" or CtagLine == ' ' or CtagLine == "\n":
                continue
            
            if len(CtagLine.split("\t")) < 7:
                continue
            
            FuncName = CtagLine.split("\t")[0]
            if CtagLine.split("\t")[3] =="f" and "function:" not in CtagLine.split("\t")[5] and "function:" not in CtagLine.split("\t")[6]:
                startline = int(CtagLine.split("\t")[4].replace("line:", "")) 
                endline = int(CtagLine.split("\t")[-1].replace("end:", "")) 
                
                if (StartLine >= startline and EndLine <= endline) or (StartLine <= startline and EndLine >= endline):
                    flag = 1
                    FuncData = "".join("".join("\n".join(FileData.split("\n")[startline-1: endline])))
                    FileName = Diff.split(".diff")[0] + "@@" + VulPatPath.split("/", 1)[-1].replace("/", "@@") + "@@" + FuncName
                    FuncFileName = Diff.split(".diff")[0] + "@@" + VulPatPath.split("/", 1)[-1].replace("/", "@@") + "@@" + FuncName + "." + VulPatPath.split(".")[-1]                         
                    
                    ## Function file save 
                    if not os.path.isfile(ResultPath + Pack + "/" + FuncFileName):
                        if not os.path.isdir(ResultPath + Pack):
                            os.mkdir(ResultPath + Pack)
    
                        ## Function data save
                        f = open(ResultPath + Pack + "/" + FuncFileName, "w")
                        f.write(FuncData)
                        f.close()

        if flag == 0:
            print("StartLine, EndLine not match: "+str(Pack) + " : " + str(Diff))

    except ValueError as e:
        print("ValueError: "+str(Pack) + " : " + str(Diff) + " : "  + str(e)) 

    return FileName


def SaveLineList(LineList, Pack, FileName, DelAddLines, Flag):
    if Pack not in LineList:
        LineList[Pack] = {}
    if FileName not in LineList[Pack]:
        LineList[Pack][FileName] = {}
    if Flag not in LineList[Pack][FileName]:
        LineList[Pack][FileName][Flag] = []
    
    LineList[Pack][FileName][Flag].extend(DelAddLines)
    
    return LineList
    

def FindLine(BeforeData, AfterData, StartSwitch):
    BeforeLine = ""
    AfterLine = ""
    
    if len(BeforeData) != 0:
        for Line in BeforeData:
            if not Line.startswith(StartSwitch):
                BeforeLine = Line
                break

    if len(AfterData) != 0:
        for Line in AfterData:
            if not Line.startswith(StartSwitch):
                AfterLine = Line
                break
    
    return BeforeLine, AfterLine


def CollectFunc():
    LineList = {} 
    VulLineList = {}
    PatLineList = {}
    
    for Pack in os.listdir(DiffPath):        
        if Pack == "BelledonneCommunications##belle-sip": 
            continue
        
        for Diff in os.listdir(DiffPath + Pack + "/"):
            os.chdir(os.getcwd()) 
            
            try:
                with open(os.path.join(DiffPath + Pack + "/", Diff), "r", encoding = "UTF-8") as f:
                    DiffData = "".join(f.readlines()) 
            except UnicodeDecodeError:
                with open(os.path.join(DiffPath + Pack + "/", Diff), "r", encoding = "ISO-8859-1") as f:
                    DiffData = "".join(f.readlines()) 
                
            os.chdir(ClonePath + Pack) 
                
            for hunk in DiffData.split("diff --git ")[1:]: 
                FilePathLine = hunk.split("\n")[0] # ex) a/net/ipv4/route.c b/net/ipv4/route.c
                IndexLine = hunk.split("\n")[1] # ex) index 6a2155b02602b1..d58dd0ec3e5302 100644
                
                if "index " not in IndexLine or ".." not in IndexLine:
                    continue
                
                VulPath = FilePathLine.split(" b/")[0]
                VulIDX  = IndexLine.split("index ")[1].split("..")[0]
                
                PatPath = "b/" + FilePathLine.split(" b/")[1]
                PatIDX  = IndexLine.split("..")[1].split(" ")[0]
                
                HunkData = hunk.split("@@")
                    
                for i in range(1, len(HunkData), 2): 
                    StartLine = 0
                    EndLine = 0
                    
                    try:
                        StartLine = int(HunkData[i].split(' -')[1].split(',')[0])
                        EndLine = StartLine + int(HunkData[i].split(' +')[1].split(',')[1]) 
                    except IndexError as e: 
                        print("IndexError: "+str(Pack) + " : " + str(Diff) + " : "  + str(e))
                        continue
                    
                    DelLines = []
                    AddLines = []
                    
                    HunkCodeList = HunkData[i+1].split("\n")
                    for IDX, EachLine in enumerate(HunkCodeList, start=0):
                        if EachLine.startswith("-") and not EachLine.startswith("--"):
                            Data = []
                            Data.append(HunkCodeList[IDX])
                            BeforeLine, AfterLine = FindLine(HunkCodeList[IDX-1:0:-1], HunkCodeList[IDX+1::], "+")
                            Data.append(BeforeLine)
                            Data.append(AfterLine)
                            DelLines.append(Data)
                        elif EachLine.startswith("+") and not EachLine.startswith("++"):
                            Data = []
                            Data.append(HunkCodeList[IDX])
                            BeforeLine, AfterLine = FindLine(HunkCodeList[IDX-1:0:-1], HunkCodeList[IDX+1::], "-")
                            Data.append(BeforeLine)
                            Data.append(AfterLine)
                            AddLines.append(Data)
                        
                    if len(DelLines) != 0: ## VulFuncs
                        VulFile = "vulfile." + VulPath.split(".")[-1]
                        Command = "git show " + VulIDX + " > " + VulFile 
                        FileName = ExtractFunc(Pack, Diff, Command, VulFile, StartLine, EndLine, VulPath, VulFuncPath, DelLines, VulLineList)
                        if FileName != "":
                            LineList = SaveLineList(LineList, Pack, FileName, DelLines, "Vul")
                    if len(AddLines) != 0: ## PatFuncs
                        PatFile = "patfile." + PatPath.split(".")[-1]
                        Command = "git show " + PatIDX + " > " + PatFile 
                        FileName = ExtractFunc(Pack, Diff, Command, PatFile, StartLine, EndLine, PatPath, PatFuncPath, AddLines, PatLineList) 
                        if FileName != "":
                            LineList = SaveLineList(LineList, Pack, FileName, AddLines, "Pat")
                       
    SaveResult(LineListPath, LineList)
    
   
def SaveResult(LineListPath, LineList):
    with open(LineListPath, "w") as f:
        json.dump(LineList, f, indent = 4)
    f.close()


def main():
    CollectFunc()

if __name__ == "__main__":
	main()