## VRUNY

VRUNY is an approach for identifying vulnerability-inducing commit via code semantic dependency analysis.

## How to prepare
You first download VRUNY.

### Requirements
* **Linux** : recommend Ubuntu 20.04
* **Git**
* **Python3** : recommend Python 3.8.10

    ```
    sudo apt-get install python3-pip
    sudo pip3 install beautifulsoup4
    sudo pip3 install requests
    sudo pip3 install websockets
    sudo pip3 install python-Levenshtein
    ```

### Ctags installation
[https://github.com/universal-ctags/ctags](https://github.com/universal-ctags/ctags)

```
cd VRUNY/
git clone https://github.com/universal-ctags/ctags.git
cd ctags/
sudo apt-get update
sudo apt-get install autoconf automake
sudo apt-get install pkg-config
./autogen.sh
./configure
make
make install
```

### Joern parser installation
[https://github.com/joernio/joern/](https://github.com/joernio/joern/)

- *Java JDK 17 installation*
    ```
    sudo apt-get update -y && sudo apt-get upgrade -y
    sudo apt install openjdk-17-jdk openjdk-17-jre
    java --version
    ```

- *Joern parser installation*
    ```
    cd VRUNY/
    mkdir joern_parser/
    cd joern_parser/
    sudo wget https://github.com/joernio/joern/releases/latest/download/joern-install.sh
    sudo apt-get install -y curl
    sudo chmod +x ./joern-install.sh
    sudo ./joern-install.sh
    joern
    ```



## How to use
Run the commands below from ***/VRUNY/***.

```
cd VRUNY/
```

We provide test dataset.
* ***/data/TestData.json***
* ***/data/clones/***



### 1. Preprocessing
*1_CollectingDiff* clones software and extracts diff files. 

```
python3 ./src/1_CollectingDiff.py
```

- check the outputs
    * ***/data/diffs/*** : Directory for storing collected CVE Diffs
    * ***/data/clones/*** : Directory for storing source codes of cloned repositories 

---

*2_ExtractingFuncLine* extracts functions and modified lines from the security patches with Ctags.

```
python3 ./src/2_ExtractingFuncLine.py
```

- check the outputs
    * ***/data/VulFuncs/*** : Directory for storing extracted function about change and deletion patches
    * ***/data/PatFuncs/*** : Directory for storing extracted function about addition patches
    * ***/output/LineList.json*** : File for storing modified lines in extracted function from the security patches



### 2. Analyzing dependency
*3_CollectingLineNum* extracts line number.


```
python3 ./src/3_CollectingLineNum.py
```

- check the outputs
    * ***/output/LineNumList.json*** : File for storing line numbers of modified lines in extracted function from the security patches

---

*4_CollectingCPG* extracts code property graphs(CPG) with Joern parser.

※ Note that you will need to run this step again about every 20 minutes (As a limitation of the ***joern --server*** command).

※ ***python3 ./4_CollectingCPG.py*** command is fine to re-run, so don't worry about it.   


※ If you get the following error, just run ***python3 ./4_CollectingCPG.py*** command again.\
***ConnectionRefusedError: [Errno 111] Connect call failed ('127.0.0.1', 8080)***

- **one terminal**
    ```
    joern --server
    ```
- **another terminal**
    ```
    python3 ./src/4_CollectingCPG.py
    ```

    - check the outputs
        * ***/data/VulCPG/*** : Directory for storing extracted cpg and ids files about function when the core lines are deleted lines
        * ***/data/PatCPG/*** : Directory for storing extracted cpg and ids files about function when the core lines are added lines

---

*5_AnalyzingDependency* extracts dependent lines and consolidates into core lines.

```
python3 ./src/5_AnalyzingDependency.py
```

- check the outputs
    * ***/output/DepList.json*** : File for storing constructed vulnerability-relevant code lines and slices about function



### 3. Analyzing commit history
*6_CollectingCommHistory* extracts commit history with git log command.

```
python3 ./src/6_CollectingCommHistory.py
```

- check the outputs
    * ***/data/CommitHistory/*** : Directory for storing collected commit history results

---

*7_AnalyzingCommHistory* traces commits in which changes occurred to each vulnerability-relevant code line.

```
python3 ./src/7_AnalyzingCommHistory.py
```

- check the outputs
    * ***/output/PotentialVICList.json*** : File for storing potential VICs about function



### 4. Identifying vulnerability-inducing commit
*8_IdentifyingVIC* identifies the vulnerability-inducing commit.

```
python3 ./src/8_IdentifyingVIC.py
```

- check the outputs
    * ***/output/VICList.json*** : File for storing identified VIC about function
