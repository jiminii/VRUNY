
def import_code_query(path, project_name=None, language=None):
    if not path:
        raise Exception('An importCode query requires a project path')
    if project_name and language:
        fmt_str = u"""importCode(inputPath=\"%s\", projectName=\"%s\",
language=\"%s\")"""
        return fmt_str % (path, project_name, language)
    if project_name and (language is None):
        fmt_str = u"""importCode(inputPath=\"%s\", projectName=\"%s\")"""
        return fmt_str % (path, project_name)
    return u"importCode(\"%s\")" % (path)

def getCPG_list(funcname):
    return u"cpg.method(\"%s\").dotCpg14.l" % (funcname)

def getCPG_graph(funcname):
    return u"cpg.method(\"%s\").plotDotCpg14" % (funcname)

def getCFG_list(funcname):
    return u"cpg.method(\"%s\").dotCfg.l" % (funcname)

def getCFG_graph(funcname):
    return u"cpg.method(\"%s\").plotDotCfg" % (funcname)

def getAST_list(funcname):
    return u"cpg.method(\"%s\").dotAst.l" % (funcname)

def getAST_graph(funcname):
    return u"cpg.method(\"%s\").plotDotAst" % (funcname)

def workspace_query():
    return "workspace"
