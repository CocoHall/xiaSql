#-- coding:UTF-8 --

from burp import IBurpExtender, ITab, IHttpListener,IScannerCheck, IMessageEditorController,IContextMenuFactory

from java.io import PrintWriter

from java.awt import GridLayout,FlowLayout
from java.awt import Component
from java.awt.event import ActionEvent
from java.awt.event import ActionListener
from java.awt.event import ItemEvent
from java.awt.event import ItemListener

from javax import swing
from javax.swing.table import AbstractTableModel
from javax.swing.table import TableModel

from java.net import URLEncoder
from java.net import URL
from java.nio.charset import StandardCharsets

import json
from thread import start_new_thread
from threading import Lock

import md5
import sys
import time
import re
reload(sys)
sys.setdefaultencoding('utf8')


log=list()#记录原始流量
log2=dict()#记录攻击流量
log3=list()#用于展现
log4_md5=list()#md5

currentlyDisplayedItem=None
requestViewer=None
responseViewer=None
secondModel=None
firstModel=None
helpers=None

errorPattern =[
    "Access Database Engine",
    "ADODB\\.Recordset'",
    "Column count doesn't match value count at row",
    "Column count doesn't match",
    "com.jnetdirect.jsql",
    "com.microsoft.sqlserver.jdbc",
    "com.mysql.jdbc",
    "DB2 SQL error",
    "Error SQL:",
    "java.sql.SQLException",
    "java.sql.SQLSyntaxErrorException",
    "macromedia.jdbc.sqlserver",
    "Microsoft Access",
    "Microsoft SQL Native Client error",
    "MySqlClient",
    "MySqlException",
    "MySQLSyntaxErrorException",
    "ODBC Microsoft Access",
    "ODBC SQL Server Driver",
    "ORA-\\d{5}",
    "Oracle error",
    "org.postgresql.jdbc",
    "PG::SyntaxError:",
    "Procedure '[^']+' requires parameter '[^']+'",
    "PSQLException",
    "SQL syntax.*?MySQL",
    "SQLite error",
    "SQLServer JDBC Driver",
    "Sybase message:",
    "SybSQLException",
    "Syntax error",
    "System.Exception: SQL Execution Error!",
    "Table '[^']+' doesn't exist",
    "the used select statements have different number of columns",
    "Unclosed quotation mark before the character string",
    "Unknown column",
    "valid MySQL result",
    "valid PostgreSQL result",
    "your MySQL server version",
    "附近有语法错误",
    "引号不完整",
    '(PLS|ORA)-[0-9][0-9][0-9][0-9]',
    '\\[CLI Driver\\]',
    '\\[DM_QUERY_E_SYNTAX\\]',
    '\\[Macromedia\\]\\[SQLServer JDBC Driver\\]',
    '\\[Microsoft\\]\\[ODBC Microsoft Access Driver\\]',
    '\\[Microsoft\\]\\[ODBC SQL Server Driver\\]',
    '\\[MySQL\\]\\[ODBC',
    '\\[SQL Server\\]',
    '\\[SqlException',
    '\\[SQLServer JDBC Driver\\]',
    '<b>Warning</b>:  ibase_',
    'A Parser Error \\(syntax error\\)',
    'ADODB\\.Field \\(0x800A0BCD\\)<br>',
    'An illegal character has been found in the statement',
    'com\\.informix\\.jdbc',
    'Data type mismatch in criteria expression.',
    'DB2 SQL error:',
    'Dynamic Page Generation Error:',
    'Dynamic SQL Error',
    'has occurred in the vicinity of:',
    'Incorrect syntax near',
    'INSERT INTO .*?',
    'internal error \\[IBM\\]\\[CLI Driver\\]\\[DB2/6000\\]',
    'java\\.sql\\.SQLException',
    'Microsoft JET Database Engine',
    'Microsoft OLE DB Provider for ODBC Drivers',
    'Microsoft OLE DB Provider for SQL Server',
    'mssql_query\\(\\)',
    'MySQL server version for the right syntax to use',
    'mysql_fetch_array\\(\\)',
    'odbc_exec\\(\\)',
    'on MySQL result index',
    'pg_exec\\(\\) \\[:',
    'pg_query\\(\\) \\[:',
    'PostgreSQL query failed:',
    'SELECT .*? FROM .*?',
    'Sintaxis incorrecta cerca de',
    'SQLSTATE=\\d+',
    'supplied argument is not a valid ',
    'Syntax error in query expression',
    'Syntax error in string in query expression',
    'System.Data.SqlClient.SqlException',
    'System\\.Data\\.OleDb\\.OleDbException',
    'Unclosed quotation mark after the character string',
    'Unexpected end of command in statement',
    'Unknown column',
    'UPDATE .*? SET .*?',
    'where clause',
    'You have an error in your SQL syntax near',
    'You have an error in your SQL syntax;'
]


class BurpExtender(IBurpExtender, ITab, IHttpListener,IScannerCheck, IMessageEditorController,IContextMenuFactory):

    def processHttpMessage(self,toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest == 0:
            if (toolFlag == 64 and self.chkbox2.isSelected()) or (toolFlag == 4 and self.chkbox3.isSelected()):
                start_new_thread(self.checkVul,(messageInfo, toolFlag,))

    def clearLog(self,actionEvent):
        global log,log2,log3,log4_md5
        log=[]#记录原始流量
        log2={}#记录攻击流量
        log3=[]#用于展现
        log4_md5=[]
        self.count=0
        firstModel.fireTableRowsInserted(0, 0)
        secondModel.fireTableRowsInserted(0, 0)
        print(u"清空列表")

    def getTabCaption(self):
        return "xia SQL"

    def getUiComponent(self):
        return self.allPanel

    def createMenuItems(self, invocation):
        responses = invocation.getSelectedMessages()
        jMenu = swing.JMenuItem("Send to xia SQL")
        jMenu.addActionListener(start_new_thread(self.checkVul,(invocation.getSelectedMessages()[0], 1024,)))

        ret = list()
        ret.append(jMenu)
        return ret

    def registerExtenderCallbacks(self, callbacks):
        global requestViewer,responseViewer,secondModel,firstModel,helpers
        #print(unicode("你好 欢迎使用 瞎注魔改版!","utf-8"))
        self.callbacks = callbacks
        helpers = callbacks.getHelpers()
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        callbacks.registerHttpListener(self)
        callbacks.setExtensionName(unicode("Xia SQL","utf-8"))

        self.lock=Lock()

        self.count=0

        secondModel = self.SecondModel()
        firstModel = self.FirstModel()


        self.allPanel = swing.JSplitPane(swing.JSplitPane.HORIZONTAL_SPLIT)
        self.leftPanel = swing.JSplitPane(swing.JSplitPane.VERTICAL_SPLIT)


        self.resultPanel = swing.JSplitPane(swing.JSplitPane.HORIZONTAL_SPLIT)

        #url、param 界面
        self.firstTable = self.FirstTable(firstModel)
        self.firstScrollPane = swing.JScrollPane(self.firstTable)

        self.tablesPanel = swing.JPanel()
        self.label0 = swing.JLabel("==>")

        self.secondTable=self.SecondTable(secondModel)
        self.secondScrollPane=swing.JScrollPane(self.secondTable)

        self.tablesPanel.add(self.firstScrollPane)
        self.tablesPanel.add(self.label0)
        self.tablesPanel.add(self.secondScrollPane)


        #右边复选框
        self.rightPanel=swing.JPanel()
        self.rightPanel.setLayout(GridLayout(22, 1))
        self.label=swing.JLabel(unicode("Xia SQL魔改版","utf-8"))
        self.chkbox2=swing.JCheckBox(unicode("监控Repeater","utf-8"))
        self.chkbox3=swing.JCheckBox(unicode("监控Proxy","utf-8"))
        self.chkbox5=swing.JCheckBox(unicode("检查md5","utf-8"))
        self.chkbox3.setSelected(True)
        self.chkbox5.setSelected(True)
        self.label4=swing.JLabel(unicode("URL字符集","utf-8"))
        self.box=swing.JComboBox(["UTF-8","GBK"])

        self.gbkPanel = swing.JPanel()
        self.gbkPanel.add(self.label4)
        self.gbkPanel.add(self.box)

        self.gbkPanel.setLayout(FlowLayout(FlowLayout.LEFT))

        self.label2=swing.JLabel(unicode("白名单域名请用,隔开（不检测）","utf-8"))
        self.textField = swing.JTextField(unicode("填写白名单域名","utf-8"))
        self.label3=swing.JLabel(unicode("白名单参数请用,隔开（不检测）","utf-8"))
        self.textField_whitleParam = swing.JTextField("dse_sessionId,dse_pageId,flowActionName,dse_operationName")


        self.btn1=swing.JButton(unicode("清空列表","utf-8"),actionPerformed=self.clearLog)

        self.chkbox4=swing.JCheckBox(unicode("启动域名白名单","utf-8"))

        self.rightPanel.add(self.label)
        self.rightPanel.add(self.chkbox2)
        self.rightPanel.add(self.chkbox3)
        self.rightPanel.add(self.chkbox5)
        self.rightPanel.add(self.gbkPanel)
        self.rightPanel.add(self.btn1)
        self.rightPanel.add(self.label2)
        self.rightPanel.add(self.textField)
        self.rightPanel.add(self.chkbox4)
        self.rightPanel.add(self.label3)
        self.rightPanel.add(self.textField_whitleParam)

        requestViewer = callbacks.createMessageEditor(self, False)
        responseViewer = callbacks.createMessageEditor(self, False)

        self.resultPanel.add(requestViewer.getComponent())
        self.resultPanel.add(responseViewer.getComponent())
        self.resultPanel.setDividerLocation(550)


        self.leftPanel.setLeftComponent(self.tablesPanel)
        self.leftPanel.setRightComponent(self.resultPanel)

        self.allPanel.setLeftComponent(self.leftPanel)
        self.allPanel.setRightComponent(self.rightPanel)
        self.allPanel.setDividerLocation(1100)

        callbacks.customizeUiComponent(self.allPanel)
        callbacks.customizeUiComponent(self.leftPanel)
        callbacks.customizeUiComponent(self.tablesPanel)
        callbacks.customizeUiComponent(self.firstTable)
        callbacks.customizeUiComponent(self.secondTable)
        callbacks.customizeUiComponent(self.firstScrollPane)
        callbacks.customizeUiComponent(self.secondScrollPane)
        callbacks.customizeUiComponent(self.rightPanel)
        callbacks.customizeUiComponent(self.resultPanel)

        callbacks.addSuiteTab(self)

        callbacks.registerHttpListener(self)
        callbacks.registerScannerCheck(self)
        callbacks.registerContextMenuFactory(self)

    def checkVul(self,baseRequestResponse, toolFlag):
        #print("checkVul")
        global secondModel,firstModel,helpers,log4_md5,log

        change_sign_1 = ""
        error_sign    = ""
        analyResult = helpers.analyzeRequest(baseRequestResponse)

        paraLists   = analyResult.getParameters()
        data_url    = analyResult.getUrl().toString()
        contentType = analyResult.getContentType()
        method      = analyResult.getMethod()

        temp_data_strarray= data_url.split("?")
        purity_url = temp_data_strarray[0]
        str_for_md5 = purity_url

        #print(purity_url)

        if self.chkbox4.isSelected():
            white_URL_list=textField.getText().split(",")
            for each in white_URL_list:
                if each in purity_url:
                    print(u"白名单URL",purity_url)
                    return

        #用于判断页面后缀是否为静态文件
        if toolFlag == 4 or toolFlag ==64:
            static_file = {"jpg","png","bmp","ico","gif","css","js","map","pdf","mp3","mp4","avi","svg","woff2","woff","otf"}
            static_file_1 =purity_url.split(".")
            static_file_2 = static_file_1[-1]

            for each in static_file:
                if each==static_file_2:
                    #print(u"当前url为静态文件："+purity_url+"\n")
                    return

        str_md5 = ""
        for para in  paraLists:
            if para.getType() == 0 or para.getType() == 1 or para.getType() == 6 :
                str_for_md5+="+"
                str_for_md5+=para.getName()
        if str_for_md5==purity_url:
            return

        str_for_md5+="+"
        str_for_md5+=method

        if self.chkbox5.isSelected()==False or toolFlag == 1024:
            str_for_md5 += str(time.time())

        str_md5 = self.getMd5(str_for_md5)
        #print(str_md5)

        self.lock.acquire()

        if str_md5 in log4_md5:
            self.lock.release()
            return
        log4_md5.append(str_md5)

        self.lock.release()

        totalRes = helpers.bytesToString(baseRequestResponse.getResponse())
        if totalRes == None:
            totalRes=""
        resbody=""
        try:
            dataOffset=totalRes.find("\r\n\r\n")
            if dataOffset>0:
                resbody = totalRes[dataOffset+4:]
            original_data_len = len(resbody)
            #print(original_data_len)
            if original_data_len <= 0:
                print("该数据包无响应")
        except Exception as e:
            original_data_len=0
            print("该数据包无响应")

        log.append(self.LogEntry(self.count, baseRequestResponse,analyResult.getUrl(),"","","",str_md5,"","run...",999,original_data_len))
        self.count += 1

        firstModel.fireTableRowsInserted(len(log), len(log))

        paraList= analyResult.getParameters()
        new_Request = baseRequestResponse.getRequest()
        iHttpService = baseRequestResponse.getHttpService()

        for para in paraList:

            if para.getType() == 0 or para.getType() == 1 :#url / post data
                key = para.getName()
                value = para.getValue()
                value_decodeurl = value
                lower_key = key.lower()
                lower_value = value.lower()

                time_1 = time_2 =0

                #key-value 中的json
                if lower_value.startswith("%7b") or lower_value.startswith("{") or lower_value.startswith("%5b") or lower_value.startswith("["):
                    if self.box.getSelectedItem().toString()=="UTF-8":
                        charset = StandardCharsets.UTF_8
                    else:
                        charset = Charset.forName("GBK")
                    tmpvalue = URLEncoder.decode(value, charset)
                    urlFlag=0
                    if len(tmpvalue)!=value:
                        urlFlag = 1

                    tmpJson = json.loads(tmpvalue)
                    gen = self.processJson(tmpJson)

                    try:
                        resultLenList = []
                        while True:
                            newJson,currentPayload,nowKey = next(gen)
                            newJson=json.dumps(newJson)
                            if urlflag==1:
                                newJson=URLEncoder.encode(newJson, charset)

                            newPara = helpers.buildParameter(key, newJson, para.getType())
                            newRequest = helpers.updateParameter(new_Request, newPara)
                            time_1 = time.time()*1000
                            requestResponse = self.callbacks.makeHttpRequest(iHttpService, newRequest)
                            time_2 = time.time()*1000

                            nowRes = helpers.bytesToString(requestResponse.getResponse())
                            if nowRes == None:
                                nowRes=""
                            nowOffset = nowRes.find("\r\n\r\n")
                            if nowOffset>0:
                                nowLen=len(nowRes)-nowOffset-4
                            else:
                                nowLen=0

                            if currentPayload == "'":
                                resultLenList=[]
                            resultLenList.append(nowLen)

                            v1,v2 = self.showDiff(requestResponse,currentPayload,int(time_2-time_1),nowKey,str_md5,original_data_len,resultLenList)
                            if change_sign_1 == "":
                                change_sign_1 = v1
                            if error_sign    == "":
                                error_sign =v2

                    except StopIteration:
                        pass
                else:
                    whitleParams = self.textField_whitleParam.getText().split(',')
                    if key in whitleParams:
                        continue

                    payloads = list()
                    payloads.append("'")
                    payloads.append("''")
                    payloads.append('"')
                    payloads.append('""')

                    if re.match(r"\d+",value):
                        payloads.append("-1")
                        payloads.append("-0")

                    if "limit" in lower_key or "order" in lower_key or "sort" in lower_key or "asc" in lower_value or "desc" in lower_value:
                        payloads.append(",111")
                        payloads.append(",1")

                    for currentPayload in payloads:

                        newPara = helpers.buildParameter(key, value+currentPayload, para.getType())
                        newRequest = helpers.updateParameter(new_Request, newPara)
                        time_1 = time.time()*1000
                        requestResponse = self.callbacks.makeHttpRequest(iHttpService, newRequest)
                        time_2 = time.time()*1000
                        nowRes = helpers.bytesToString(requestResponse.getResponse())
                        if nowRes == None:
                            nowRes=""
                        nowOffset = nowRes.find("\r\n\r\n")
                        if nowOffset>0:
                            nowLen=len(nowRes)-nowOffset-4
                        else:
                            nowLen=0

                        if currentPayload == "'":
                            resultLenList=[]
                        resultLenList.append(nowLen)
                        v1,v2 = self.showDiff(requestResponse,currentPayload,int(time_2-time_1),key,str_md5,original_data_len,resultLenList)
                        if change_sign_1 == "":
                            change_sign_1 = v1
                        if error_sign    == "":
                            error_sign =v2

        if contentType == 4:#json

            headers=analyResult.getHeaders()

            totalRes = helpers.bytesToString(baseRequestResponse.getRequest())
            postbody="{}"
            dataOffset=totalRes.find("\r\n\r\n")
            if dataOffset>0:
                postbody = totalRes[dataOffset+4:]

            tmpJson = json.loads(postbody)
            gen = self.processJson(tmpJson)
            #print(tmpJson)
            try:
                while True:
                    newJson,currentPayload,nowKey = next(gen)
                    newJson=json.dumps(newJson)
                    newRequest = helpers.buildHttpMessage(headers,newJson)

                    time_1 = time.time()*1000
                    requestResponse = self.callbacks.makeHttpRequest(iHttpService, newRequest)
                    time_2 = time.time()*1000
                    nowRes = helpers.bytesToString(requestResponse.getResponse())
                    if nowRes == None:
                        nowRes=""
                    nowOffset = nowRes.find("\r\n\r\n")
                    if nowOffset>0:
                        nowLen=len(nowRes)-nowOffset-4
                    else:
                        nowLen=0
                    if currentPayload == "'":
                        resultLenList=[]
                    resultLenList.append(nowLen)

                    v1,v2 = self.showDiff(requestResponse,currentPayload,int(time_2-time_1),nowKey,str_md5,original_data_len,resultLenList)
                    if change_sign_1 == "":
                        change_sign_1 = v1
                    if error_sign    == "":
                        error_sign =v2

            except StopIteration:
                pass
            except Exception as e:
                print(e)

        for logEntry in log:
            if str_md5==logEntry.data_md5:
                logEntry.setState("end!" + change_sign_1+error_sign)

        nowRow = self.firstTable.getSelectedRow()

        firstModel.fireTableRowsInserted(len(log), len(log))
        firstModel.fireTableDataChanged()

        if nowRow>=0 and nowRow<len(log):
            self.firstTable.setRowSelectionInterval(nowRow,nowRow)

    def processJson(self,data):

        currentPayload=""
        for each in data:

            if type(data[each]) == dict :
                tmp=data[each]
                gen = self.processJson(data[each])
                try:
                    while True:
                        result,currentPayload,nowKey = next(gen)
                        data[each]=result
                        yield data,currentPayload,nowKey
                except StopIteration:
                    data[each]=tmp

            if type(data[each]) == list:
                for i in range(len(data[each])):
                    if type(data[each][i]) in [str,unicode]:
                        tmp=data[each][i]
                        payloads=["'","''",'"','""']
                        if re.match(r"\d+",tmp):
                            payloads.append("-1")
                            payloads.append("-0")
                        if "limit" in each.lower() or "order" in each.lower() or "sort" in each.lower() or "asc" in tmp.lower() or "desc" in tmp.lower():
                            payloads.append(",111")
                            payloads.append(",1")

                        for currentPayload in payloads:
                            data[each][i]=tmp+currentPayload
                            yield data,currentPayload,each
                        data[each][i]=tmp

                    if type(data[each][i]) in [list,dict]:
                        tmp=data[each][i]
                        gen = self.processJson(data[each][i])
                        try:
                            while True:
                                result,currentPayload,nowKey = next(gen)
                                data[each][i]=result
                                yield data,currentPayload,nowKey
                        except StopIteration:
                            data[each][i]=tmp

            if type(data[each])  in [str,unicode]:

                tmpStr=data[each].lower()

                if tmpStr.startswith("{") or tmpStr.startswith("%7b") or tmpStr.startswith("[") or tmpStr.startswith("%5b"):
                    #json
                    urlflag=0
                    originStr=data[each]
                    if self.box.getSelectedItem().toString()=="UTF-8":
                        charset = StandardCharsets.UTF_8
                    else:
                        charset = Charset.forName("GBK")
                    tmpStr = URLEncoder.decode(data[each], charset)
                    if len(tmpStr)!=len(data[each]):
                        urlflag=1

                    tmp=json.loads(tmpStr)
                    gen = self.processJson(tmp)
                    try:
                        while True:
                            result,currentPayload,nowKey = next(gen)
                            result=json.dumps(result)
                            if urlflag:
                                result=URLEncoder.encode(data[each], charset)
                            data[each]=result
                            yield data,currentPayload,nowKey
                    except StopIteration:
                        data[each]=originStr
                else:
                    tmp=data[each]
                    whitleParams = self.textField_whitleParam.getText().split(',')
                    if each in whitleParams:
                        continue
                    payloads=["'","''",'"','""']
                    if re.match(r"\d+",tmp):
                        payloads.append("-1")
                        payloads.append("-0")
                    if "limit" in each.lower() or "order" in each.lower() or "sort" in each.lower() or "asc" in tmp.lower() or "desc" in tmp.lower():
                        payloads.append(",111")
                        payloads.append(",1")

                    for currentPayload in payloads:
                        data[each]=tmp+currentPayload
                        yield data,currentPayload,each
                    data[each]=tmp

            if type(data[each]) in [int,float]:
                tmp=data[each]
                whitleParams = self.textField_whitleParam.getText().split(',')
                if each in whitleParams:
                    continue
                payloads=["'","''",'"','""',"-1","-0"]

                if "limit" in each.lower() or "order" in each.lower() or "sort" in each.lower():
                    payloads.append(",111")
                    payloads.append(",1")

                for currentPayload in payloads:
                    data[each]=str(tmp)+currentPayload
                    yield data,currentPayload,each
                data[each]=tmp

    def showDiff(self,requestResponse,currentPayload,diffTime,key,str_md5,original_data_len,resultLenList):
        global log2,helpers,errorPattern
        change=0
        change_sign   = ""
        change_sign_1 = ""
        error_sign    = ""
        #   '   ''  "   ""  -1  -0  ,111    ,1
        if len(resultLenList)%2==0:
            if resultLenList[-2] != original_data_len and resultLenList[-1] == original_data_len:
                change_sign = unicode("✔ ==> ?","utf-8")
            elif resultLenList[-2] != resultLenList[-1]:
                change_sign = unicode("✔ ","utf-8") + str(resultLenList[-2] - resultLenList[-1])

            if diffTime>8000:
                change_sign+=" time >8"
            if change_sign!="":
                change_sign_1 = unicode(" ✔","utf-8")

        res = helpers.bytesToString(requestResponse.getResponse())

        for each in errorPattern:
            pattern = re.compile(each, re.IGNORECASE)
            if pattern.search(res):
                error_sign = " Err"
                break

        if str_md5 not in log2:
            log2[str_md5]=[]
        log2[str_md5].append(self.LogEntry(self.count, requestResponse,
                helpers.analyzeRequest(requestResponse).getUrl(),
                key, currentPayload, change_sign+error_sign, str_md5,diffTime, "end",
                helpers.analyzeResponse(requestResponse.getResponse()).getStatusCode(),resultLenList[-1]))
        return change_sign_1,error_sign

    def getMd5(self,key):
        m = md5.new()
        m.update(key)
        return m.hexdigest()

    def getRequest(self):
        return currentlyDisplayedItem.getRequest()

    def getResponse(self):
        return currentlyDisplayedItem.getResponse()

    def getHttpService()
        return currentlyDisplayedItem.getHttpService()

    class SecondModel (AbstractTableModel):

        def getRowCount(self,):
            global log3
            return len(log3)

        def getColumnCount(self,):
            return 6

        def getColumnName(self,columnIndex):
            if columnIndex==0:
                return unicode("参数","utf-8")
            elif columnIndex==1:
                return unicode("payload","utf-8")
            elif columnIndex==2:
                return unicode("返回包长度","utf-8")
            elif columnIndex==3:
                return unicode("变化","utf-8")
            elif columnIndex==4:
                return unicode("用时","utf-8")
            elif columnIndex==5:
                return unicode("响应码","utf-8")
            else:
                return ""

        def getColumnClass(self,columnIndex):
            return str

        def getValueAt(self,rowIndex, columnIndex):
            global log3
            logEntry = log3[rowIndex]

            if columnIndex == 0:
                    return logEntry.parameter
            elif columnIndex == 1:
                    return logEntry.value
            elif columnIndex == 2:
                if logEntry.requestResponse.getResponse()==None:
                    return 0
                tmp = helpers.bytesToString(logEntry.requestResponse.getResponse())
                return len(tmp)-tmp.find("\r\n\r\n")-4
            elif columnIndex == 3:
                    return logEntry.change
            elif columnIndex == 4:
                    return logEntry.times
            elif columnIndex == 5:
                    return logEntry.response_code
            else:
                return ""

    class FirstModel (AbstractTableModel):

        def getRowCount(self):
            return len(log)

        def getColumnCount(self):
            return 5

        def getColumnName(self,columnIndex):
            if columnIndex==0:
                return unicode("#","utf-8")
            elif columnIndex==1:
                return unicode("时间","utf-8")
            elif columnIndex==2:
                return unicode("接口","utf-8")
            elif columnIndex==3:
                return unicode("返回包长度","utf-8")
            elif columnIndex==4:
                return unicode("状态","utf-8")
            else:
                return ""

        def getColumnClass(self,columnIndex):
            return str

        def getValueAt(self,rowIndex, columnIndex):
            global helpers
            logEntry = log[rowIndex]
            if columnIndex==0:
                return logEntry.id
            elif columnIndex==1:
                return time.strftime("%H:%M:%S",time.localtime(logEntry.time))
            elif columnIndex==2:
                url =URL(logEntry.url.toString())
                return url.getPath()
            elif columnIndex==3:
                if logEntry.requestResponse.getResponse()==None:
                    return 0
                tmp = helpers.bytesToString(logEntry.requestResponse.getResponse())
                return len(tmp)-tmp.find("\r\n\r\n")-4

            elif columnIndex==4:
                return logEntry.state
            else:
                return ""

    class FirstTable(swing.JTable):

        def changeSelection(self,row, col, toggle, extend):
            global secondModel,firstModel,log,log2,log3,currentlyDisplayedItem
            logEntry = log[row]
            data_md5_id = logEntry.data_md5
            if data_md5_id in log2:
                log3=log2[data_md5_id]
            else:
                log3=[]

            secondModel.fireTableRowsInserted(len(log3), len(log3))
            secondModel.fireTableDataChanged()
            requestViewer.setMessage(logEntry.requestResponse.getRequest(), True)
            if logEntry.requestResponse.getResponse()==None:
                responseViewer.setMessage("", False)
            else:
                responseViewer.setMessage(logEntry.requestResponse.getResponse(), False)

            currentlyDisplayedItem = logEntry.requestResponse

            swing.JTable.changeSelection(self, row, col, toggle, extend)

    class SecondTable(swing.JTable):
        def __init__(self,secondTableModel):
            swing.JTable.__init__(self,secondTableModel)

        def changeSelection(self, row, col, toggle, extend):
            global requestViewer,responseViewer,log3,currentlyDisplayedItem
            logEntry = log3[row]
            requestViewer.setMessage(logEntry.requestResponse.getRequest(), True)
            if logEntry.requestResponse.getResponse()==None:
                responseViewer.setMessage("", False)
            else:
                responseViewer.setMessage(logEntry.requestResponse.getResponse(), False)
            currentlyDisplayedItem = logEntry.requestResponse

            swing.JTable.changeSelection(self, row, col, toggle, extend)

    class LogEntry():

        def __init__(self,id, requestResponse, url,parameter,value,change,data_md5,times,state,response_code,contentlen):
            self.id              = id
            self.time            = time.time()
            self.requestResponse = requestResponse
            self.contentlen      = contentlen
            self.url             = url
            self.parameter       = parameter
            self.value           = value
            self.change          = change
            self.data_md5        = data_md5
            self.times           = times
            self.state           = state
            self.response_code   = response_code

        def setState(self,state):
            self.state = state
