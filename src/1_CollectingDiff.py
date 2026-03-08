import os
import json
from bs4 import BeautifulSoup
import urllib.request
import subprocess

homePath = os.getcwd() ## /VRUNY/
DataPath = homePath + "/data/TestData.json"
#=# Output
DiffPath = homePath + "/data/diffs/"
ClonePath = homePath + "/data/clones/"

shouldMake = [DiffPath, ClonePath]
for eachRepo in shouldMake:
	if not os.path.isdir(eachRepo):
		os.mkdir(eachRepo)


def ExtractPackName(URL):
	Pack = ""
	Clone = ""

	if "github.com" in URL and "commit" in URL:
		Pack = URL.split("github.com/")[1].split("/")[0] + "##" + URL.split("github.com/")[1].split("/")[1]
		Clone = "git clone https://github.com/" + Pack.replace("##","/") + ".git"

	return Pack, Clone


def CloneRepo(Pack, Clone):
    if os.path.isdir(ClonePath + Pack):
        return
    if not Clone.startswith('git clone'):
        Clone = 'git clone ' + Clone
    elif Clone.startswith("git clonegit"):
        Clone = Clone.replace("git clonegit", "git clone git")

    try:
        print ("[-] Now cloning " + Pack + "..")
        Result = subprocess.check_output(Clone + ' ' + ClonePath + Pack, stderr=subprocess.STDOUT, shell=True)
    except subprocess.CalledProcessError as e:
        print (e)


def CollectDiff(URLS):
    for CVE in URLS:
        print("CVE: "+str(CVE))
        
        for URL in URLS[CVE]:
            print("URL: "+str(URL))
            Pack, Clone = ExtractPackName(URL)

            if "github.com" in URL and "commit" in URL:
                ParsingDiff = URL + ".diff"
            else:
                continue
            
            try:
                soup = BeautifulSoup(urllib.request.urlopen(ParsingDiff).read(), 'html.parser')
                idx = 0
                # Some CVEs have multiple diffs
                FileName = CVE + '_' + str(idx) + ".diff"
                
                while True: 
                    if not os.path.isdir(DiffPath + Pack):
                        os.mkdir(DiffPath + Pack)
                    if FileName in os.listdir(DiffPath + Pack):
                        FileName = FileName.replace(str(idx) + ".diff", str(idx + 1) + ".diff")
                        idx += 1
                    else:
                        break
                
                # We only consider C/C++ related patches
                DiffBody = soup.text

                DiffData = DiffBody.split('diff --git a')[0] + "\n"
                flag = 0
                for chunks in DiffBody.split('diff --git a')[1:]:
                    extension = chunks.split('\n')[0]
                    if extension.endswith('.c') or extension.endswith('.cc') or extension.endswith('.cpp'):
                        DiffData += "diff --git a" + chunks + "\n"
                        flag = 1

                if flag == 1:
                    f = open(DiffPath + Pack + '/' + FileName, 'w')
                    f.write("URL:" + URL + '\n')
                    f.write(DiffData)
                    f.close()

                    CloneRepo(Pack, Clone)

            except:
                pass
            
    print ('[+] Done: Collecting Diff Files.')
    

def main():
    f = open(DataPath, 'r')
    URLS = json.load(f)
    CollectDiff(URLS) 

if __name__ == "__main__":
	main()