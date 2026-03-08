import json 
import os 
import re

homePath = os.getcwd() ## /VRUNY/
DiffPath = homePath + "/data/diffs/"
CommHistoryPath = homePath + "/data/CommitHistory/"
CommHashPath = homePath + "/output/PotentialVICList.json"
#=# Output
VICPath = homePath + "/output/VICList.json"


def ExtractCommList(CommListData):
    CommList = {} 
    for key in CommListData.keys():
        CommList.update(CommListData[key])
        
    CommList = {k: CommList[k] for k in sorted(CommList, key=lambda x: int(x))}
            
    return CommList


def ConfigureData(VulPatCommList, CommList):
    f_CommList = {}
    except_list = []
    for key, value in CommList.items():
        f_CommList[key+"@@"+value] = []
    
    for CodeLine, EachCommList in VulPatCommList.items():
        if len(EachCommList) == 0:
            except_list.append(CodeLine)
            continue
        
        LastKey = list(EachCommList.keys())[-1]
        
        for KeyValue in list(f_CommList.keys()):
            Key = KeyValue.split("@@")[0]
            Value = KeyValue.split("@@")[1]
            
            if int(LastKey) >= int(Key):
                f_CommList[Key+"@@"+Value].append(CodeLine)

    return f_CommList


def CalculateSim(PathPair, f_CommList, CountList):     
    for CommHash, CodeLineList in f_CommList.items():
        MatchCount = 0
        for EachPair in PathPair:
            CompareSet = set(CodeLineList) & set(EachPair)
            if len(CompareSet) == len(EachPair): 
                MatchCount += 1 
    
        TotalCount = len(PathPair)
        try: 
            Sim = round((MatchCount/TotalCount), 1)
        except ZeroDivisionError:
            Sim = 0.0
        
        if CommHash not in CountList:
            CountList[CommHash] = {}
        CountList[CommHash] = Sim
    
    return CountList


def ExtractingVIC(CountList):    
    VIC = ""
    
    if len(CountList) == 0:
        return VIC 
    
    if CountList[list(CountList.keys())[0]] >= 0.3:
        for CommHash, Sim in CountList.items():
            if Sim >= 0.3:
                VIC = CommHash
    else:
        if CountList[list(CountList.keys())[0]] == 0.2:
            for CommHash, Sim in CountList.items():
                if Sim >= 0.2:
                    VIC = CommHash
        elif CountList[list(CountList.keys())[0]] == 0.1:
            for CommHash, Sim in CountList.items():
                if Sim >= 0.1:
                    VIC = CommHash
        elif CountList[list(CountList.keys())[0]] == 0.0:
            VIC = list(CountList.keys())[0]
        else:
            print("VICError")
    
    return VIC 


def SaveVICList(VICList, Pack, FileName, Flag, TargetData, CountList, VIC):
    if Pack not in VICList:
        VICList[Pack] = {}
    if FileName not in VICList[Pack]:
        VICList[Pack][FileName] = {}
    if "VFC" not in VICList[Pack][FileName]:
        VICList[Pack][FileName].update(TargetData)

    VICList[Pack][FileName][Flag+"_CountList"] = CountList 
    VICList[Pack][FileName]["VIC"] = VIC 
    
    return VICList


def IdentifyVIC(CommHashData):
    VICList = {}
    
    for Pack in CommHashData:
        for FileName in CommHashData[Pack]:             
            print("FileName: "+str(FileName))

            if "Vul_CommList" in CommHashData[Pack][FileName]:
                CommList = ExtractCommList(CommHashData[Pack][FileName]["Vul_CommList"])
                f_CommList = ConfigureData(CommHashData[Pack][FileName]["Vul_CommList"], CommList)
                
                CountList = {}
                if "Vul_PathPair" in CommHashData[Pack][FileName] and \
                    len(CommHashData[Pack][FileName]["Vul_PathPair"]) != 0: 
                        CountList = CalculateSim(CommHashData[Pack][FileName]["Vul_PathPair"], f_CommList, CountList)   
                        VIC = ExtractingVIC(CountList)
                        VICList = SaveVICList(VICList, Pack, FileName, "Vul", CommHashData[Pack][FileName], CountList, VIC)              
                if "Vul_PathPair" not in CommHashData[Pack][FileName] or \
                    len(CommHashData[Pack][FileName]["Vul_PathPair"]) == 0:  
                        if len(f_CommList) == 0:
                            VICList = SaveVICList(VICList, Pack, FileName, "Vul", CommHashData[Pack][FileName], CountList, "")
                        else:
                            VIC = list(f_CommList.keys())[-1]

                            VICList = SaveVICList(VICList, Pack, FileName, "Vul", CommHashData[Pack][FileName], CountList, VIC)
            if "Pat_CommList" in CommHashData[Pack][FileName]: 
                CommList = ExtractCommList(CommHashData[Pack][FileName]["Pat_CommList"])
                f_CommList = ConfigureData(CommHashData[Pack][FileName]["Pat_CommList"], CommList)
                
                CountList = {}
                if "Pat_PathPair" in CommHashData[Pack][FileName] and \
                    len(CommHashData[Pack][FileName]["Pat_PathPair"]) != 0: 
                        CountList = CalculateSim(CommHashData[Pack][FileName]["Pat_PathPair"], f_CommList, CountList) 
                        VIC = ExtractingVIC(CountList)
                        VICList = SaveVICList(VICList, Pack, FileName, "Pat", CommHashData[Pack][FileName], CountList, VIC)                 
                if "Pat_PathPair" not in CommHashData[Pack][FileName] or \
                    len(CommHashData[Pack][FileName]["Pat_PathPair"]) == 0:  
                        if len(f_CommList) == 0:
                            VICList = SaveVICList(VICList, Pack, FileName, "Pat", CommHashData[Pack][FileName], CountList, "")
                        else:
                            VIC = list(f_CommList.keys())[-1] 

                            VICList = SaveVICList(VICList, Pack, FileName, "Pat", CommHashData[Pack][FileName], CountList, VIC)
    
    return VICList


def SaveResult(VICList, VICPath):
    with open(VICPath, "w") as f:
        json.dump(VICList, f, indent = 4)
    f.close()


def main():
    f = open(CommHashPath, 'r')
    CommHashData = json.load(f)
    
    VICList = IdentifyVIC(CommHashData)
    SaveResult(VICList, VICPath)


if __name__ == "__main__":
	main()
