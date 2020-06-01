package burp;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class BurpExtender implements IBurpExtender, IScannerCheck
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private static BurpExtender extender;

    //
    // implement IBurpExtender
    //
    
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;
        
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
        
        // set our extension name
        callbacks.setExtensionName("SameSite Reporter");
        
        // register ourselves as a custom scanner check
        callbacks.registerScannerCheck(this);

        BurpExtender.extender = this;
    }

    //
    // implement IScannerCheck
    //
    
    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        byte[] response = baseRequestResponse.getResponse();
        IResponseInfo responseInfo = helpers.analyzeResponse(response);
        List<String> headers = responseInfo.getHeaders();

        List<IScanIssue> issues = new ArrayList();

        List<String> sameSiteNone = new ArrayList<String>();
        List<int[]> sameSiteNoneMatches = new ArrayList<int[]>();

        List<String> sameSiteMissing = new ArrayList<String>();
        List<int[]> sameSiteMissingMatches = new ArrayList<int[]>();

        String title = "";
        String details = "";
        String issueBackground = "";
        String remediationBackground = "";
        String severity = "";
        String sameSiteValues = "<strong>Possible SameSite values</strong><ul>" +
            "<li><b>None:</b> When a cookie is set to SameSite=None, it will be transmitted from requests originating from " +
            "all origins. As such, requests originating from third-party websites will include the affected cookie. An  attacker" +
            "can potentially exploit the application with a Cross-Site Request Forgery attack when a session cookie's SameSite " +
            "flag is set to None.</li>" +
            "<li><b>Lax:</b> When a cookie is set to SameSite=Lax, it will <b>only</b> be transmitted from third party origins " +
            "if the request is using the \"GET\" HTTP method. A \"POST\" request from a.com to b.com would therefore not include " +
            "the cookie. <i>In most browsers, this is the default value when the SameSite flag is ommited.</i></li>" +
            "<li><b>Strict:</b> When a cookie is set to SameSite=Strict, it will <b>only</b> be transmitted if the request is " +
            "initiated from the same domain the cookie was first set from. This also affects \"GET\" requests, meaning if a " +
            "user clicks on a link on a.com that points to b.com, the browser will not send the cookies previously set " +
            "on b.com, unlike with SameSite=Lax. This introduces poor user experience and therefore should probably only be " +
            "used in highly-sensitive applications, such as banking software.</li></ul>";

        for (String header : headers) {
            String[] tokenizer = header.split(":", 2);
            String headerName = tokenizer[0].trim();

            if (headerName.equalsIgnoreCase("set-cookie")) {
                String setCookie = tokenizer[1].trim();
                Cookie c = new Cookie(setCookie);

                // Found a valid issue with SameSite
                if (c.issue) {
                    int headerStart = helpers.indexOf(response, header.getBytes(), true, 0, response.length);

                    if (c.sameSite == "missing") {
                        sameSiteMissing.add(c.name);
                        sameSiteMissingMatches.add(new int[] {headerStart, headerStart + header.length()});


                    } else if (c.sameSite == "none") {
                        sameSiteNone.add(c.name);
                        sameSiteNoneMatches.add(new int[] {headerStart, headerStart + header.length()});
                    }
                }

            }
        }

        if (sameSiteMissing.size() > 0) {
            title = "Cookie without SameSite flag set";

            details = "<p>The following cookies were issued by the application and did not have the SameSite flag set:</p>" +
                listifyStrings(sameSiteMissing) +
                "The content of the cookie is not analyzed by this extension, assessing the sensitivity of the cookie is " +
                "an exercise left to the tester.";

            issueBackground = "This cookie did not have a SameSite value defined. Modern browers will set the default " +
                "SameSite value to \"Lax\" when it is not declared by the server. See the possible values for the " +
                "\"SameSite\" flag below. The SameSite cookie flag is used to limit cookie transmition when a request "+
                "originates from a third-party origin. This is an effective mechanism to protect against some client-side " +
                "attacks, such as Cross-Site Request Forgery (CSRF).<br/><br/>" +
                sameSiteValues; 

            remediationBackground = "The SameSite flag must be added to the Set-Cookie header when it is first defined. This can " +
                "be done by simply appending \"; SameSite=Lax\" or \"; SameSite=Strict\" to the Set-Cookie header.<br/>" +
                "See https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html" +
                "#samesite-cookie-attribute for more details.";

            severity = "Information";

            issues.add(new CustomScanIssue(baseRequestResponse.getHttpService(),
                                           helpers.analyzeRequest(baseRequestResponse).getUrl(), 
                                           new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null,
                                                                                               sameSiteMissingMatches) }, 
                                           title,
                                           details,
                                           issueBackground,
                                           remediationBackground,
                                           severity));
        } 

        if (sameSiteNone.size() > 0) {
            title = "Cookie with SameSite set to None";

            details = "<p>The following cookies were issued by the application and explicitly set the SameSite value to None:</p>" +
                listifyStrings(sameSiteNone) +
                "The content of the cookie is not analyzed by this extension, assessing the sensitivity of the cookie is " +
                "an exercise left to the tester.";

            issueBackground = "This cookie was explicitly set with the SameSite value to None. All browers will send this " +
                "cookie when a request is originating from a third-party website, no matter the HTTP method. Depending on the " +
                "sensitivity of the cookie's value, the application could potentially be exploited with some common client-side " +
                "attacks, such as Cross-Site Request Forgery (CSRF). See the possible values for the \"SameSite\" flag below. " +
                "The SameSite cookie flag is used to limit cookie transmition when a request originates from a third-party origin." +
                "<br/><br/>" +
                sameSiteValues;

            remediationBackground = "The SameSite flag should be one of \"Lax\" or \"Strict\". In order to change it, simply " +
                "change that value when the cookie is first set, by appending \"; SameSite=Lax\" or \"; SameSite=Strict\" at " +
                "the end of the Set-Cookie header." +
                "See https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html" +
                "#samesite-cookie-attribute for more details.";

            severity = "Low";

            issues.add(new CustomScanIssue(baseRequestResponse.getHttpService(),
                                           helpers.analyzeRequest(baseRequestResponse).getUrl(), 
                                           new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null,
                                                                                               sameSiteNoneMatches) }, 
                                           title,
                                           details,
                                           issueBackground,
                                           remediationBackground,
                                           severity));
        }

        return issues;
    
    }

    private String listifyStrings(List<String> listContent) {
        // Returns a HTML list of the input 

        String html = "<ul>";
        for (String elem : listContent) {
            html += "<li>" + elem + "</li>";
        }
        html += "</ul>";
    
        return html;
    }


    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return new ArrayList<IScanIssue>();
    }
}



//
// class implementing IScanIssue to hold our custom scan issue details
//
class CustomScanIssue implements IScanIssue
{
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private String issueBackground;
    private String remediationBackground;
    private String severity;

    public CustomScanIssue(
                           IHttpService httpService,
                           URL url, 
                           IHttpRequestResponse[] httpMessages, 
                           String name,
                           String detail,
                           String issueBackground,
                           String remediationBackground,
                           String severity) {
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.name = name;
        this.detail = detail;
        this.issueBackground = issueBackground;
        this.remediationBackground = remediationBackground;
        this.severity = severity;
    }
    
    @Override
    public URL getUrl() {
        return url;
    }

    @Override
    public String getIssueName() {
        return name;
    }

    @Override
    public int getIssueType() {
        return 0;
    }

    @Override
    public String getSeverity() {
        return severity;
    }

    @Override
    public String getConfidence() {
        return "Certain";
    }

    @Override
    public String getIssueBackground() {
        return issueBackground;
    }

    @Override
    public String getRemediationBackground() {
        return remediationBackground;
    }

    @Override
    public String getIssueDetail() {
        return detail;
    }

    @Override
    public String getRemediationDetail() {
        return null;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService() {
        return httpService;
    }
    
}
