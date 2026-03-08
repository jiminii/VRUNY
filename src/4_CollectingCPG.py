import os
import sys
import shutil

import json

from cpgqls_client import CPGQLSClient, import_code_query, workspace_query, getCFG_list, getCFG_graph, getCPG_list, getCPG_graph, getAST_list, getAST_graph

homePath = os.getcwd() ## /VRUNY/
LineNumListPath = homePath + "/output/LineNumList.json"
VulFuncPath = homePath + "/data/VulFuncs/"
PatFuncPath = homePath + "/data/PatFuncs/"
#=# Output
VulCPGPath = homePath + "/data/VulCPG/"
PatCPGPath = homePath + "/data/PatCPG/"


shouldMake = [VulCPGPath, PatCPGPath]
for eachRepo in shouldMake:
	if not os.path.isdir(eachRepo):
		os.mkdir(eachRepo)

server_endpoint = "localhost:8080"
basic_auth_credentials = ("username", "password") 
client = CPGQLSClient(server_endpoint, auth_credentials=basic_auth_credentials)


def ExtractCPG(DataPath, ResPath, Dataset, Flag):
    for Pack in Dataset: 
        for FileName in Dataset[Pack]:             
            if Flag not in Dataset[Pack][FileName]:
                continue
            
            if Pack in os.listdir(ResPath) and \
                (FileName + '_cpg.txt') in os.listdir(ResPath + Pack):
                print (Pack + " : " + FileName + ".. exist")
                continue
            
            print (Pack + " : " + FileName + ".. start")
            Func = FileName.split('@@')[-1].split(".c")[0]
            
            FuncFilePath = DataPath + Pack + "/" + FileName
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
                                    continue
            
            header = FuncData.split("(")[0]
            if "::" in header:
                Func = header.split("::")[1]
                
            query = import_code_query(DataPath + Pack + "/", FileName)
            result_import = client.execute(query)
            
            query = "run.ossdataflow"
            result = client.execute(query)

            query = getCPG_list(Func) 
            result_cpg = client.execute(query)
            
            try:
                cpgres = str(result_cpg['stdout'])
            except:
                print (Pack + " : " + FileName + ".. fail")
                continue
            
            if not os.path.isdir(ResPath + Pack):
                os.mkdir(ResPath + Pack)
            
            f1 = open(ResPath + Pack + "/" + FileName + "_cpg.txt", "w") 
            f1.write(cpgres)
            f1.close()
            
            f2 = open(ResPath + Pack + "/" + FileName + "_ids.txt", 'w') 
            query = 'cpg.method("'+Func+'").call.l'
            result_ids = client.execute(query)
            idsres = str(result_ids['stdout'])

            f2.write(idsres)
            f2.close()    

def main(): 
    f1 = open(LineNumListPath, 'r')
    Dataset = json.load(f1)
    
    ExtractCPG(VulFuncPath, VulCPGPath, Dataset, "Vul")
    ExtractCPG(PatFuncPath, PatCPGPath, Dataset, "Pat")

if __name__ == "__main__":
	main()
