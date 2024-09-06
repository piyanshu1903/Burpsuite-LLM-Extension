from burp import IBurpExtender, IHttpListener
import json
import webbrowser
from javax.swing import JOptionPane
import urllib2

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.registerHttpListener(self)
        callbacks.setExtensionName("Request interceptor")
        callbacks.issueAlert("All Modules integrated")
        self.intercept_enabled = False

    def getRequestHeadersAndBody(self, content):
        request = content.getRequest()
        request_data = self._helpers.analyzeRequest(request)
        headers = request_data.getHeaders() or {}
        headers_dict = {}
        for header in headers:
            parts = header.split(':', 1)
            if len(parts) == 2:
                key, value = parts[0].strip(), parts[1].strip()
                headers_dict[key] = value
        body = request[request_data.getBodyOffset():].tostring()
        
        # Extracting URL and request type
        url = self._helpers.analyzeRequest(content).getUrl().toString()
        request_type = request_data.getMethod()
        
        return headers_dict, body, url, request_type
  
    def processHttpMessage(self, tool, is_request, content):
        if not is_request:  # We only want to process requests
            return

        headers, body, url, request_type = self.getRequestHeadersAndBody(content)
        url_status=0

        # Accessing the 'Host' header from the dictionary
        host = headers.get('Host')

        # Check if the URL contains "bwapp" 
        # Currently Monitoring only single website.
        
        if ("bwapp" in host):
            with open('log.txt', "a") as file:
                file.write("URL: " + url + "\n")
                file.write("Request Type: " + request_type + "\n")
                file.write(str(headers))
                #check previous flag status ("if flagged earlier")
                check_flag_data = json.dumps({"url":url})
                check_request = urllib2.Request('http://127.0.0.1:8083/check_flag', check_flag_data, {'Content-Type': 'application/json'})
                check_response = urllib2.urlopen(check_request)
                check_response_read=check_response.read()
                prev_url_status = json.loads(check_response_read)['result']
                prev_url_status = "threat"

                if(prev_url_status=="threat"):
                    # perform strict prompt

                    request_json_data = json.dumps({'url':url,'body':headers,'Request':request_type})
                    openai_request = urllib2.Request('http://127.0.0.1:8083/openai', request_json_data, {'Content-Type': 'application/json'})
                    openai_response = urllib2.urlopen(openai_request)
                    openai_response_code=openai_response.getcode()
                    file.write("\n"+str(openai_response_code))
                    openai_datarecvd=openai_response.read()
                    url_status = json.loads(openai_datarecvd)['result']
                    file.write("\n"+str(url_status))
                    if(url_status==1):
                        #flag the url for future reference
                        flag_red_data = json.dumps({"url":url})
                        flag_red_request = urllib2.Request('http://127.0.0.1:8083/flag_red', flag_red_data, {'Content-Type': 'application/json'})
                        flag_red_response = urllib2.urlopen(flag_red_request)
                        flag_red_response_code=flag_red_response.getcode()
                        if(flag_red_response_code==200):
                            JOptionPane.showMessageDialog(None, "Threat Detected", "Warning", JOptionPane.WARNING_MESSAGE)
                            webbrowser.open("http://127.0.0.1:8083/halted",new=0,)
                            new_request = self._helpers.buildHttpMessage(
                                ["GET ", "", ""],
                                b"",  # Empty body
                            )
                            content.setRequest(new_request)
                            return None
                        else:
                            JOptionPane.showMessageDialog(None, "Threat Detected but unable to flag.", "Warning", JOptionPane.WARNING_MESSAGE)
                            webbrowser.open("http://127.0.0.1:8083/halted",new=0,)
                            new_request = self._helpers.buildHttpMessage(
                                ["GET ", "", ""],
                                b"",  # Empty body
                            )
                            content.setRequest(new_request)
                            return None
                    else:
                        #checked the live status of url
                        print("url is safe")
                else:
                    #url is not flagged yet
                    print("perform lineant prompt")
        print("no issue")
        


