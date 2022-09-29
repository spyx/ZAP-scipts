// AddListener finder 
// Script was duplicated from find IBAN 


function scan(ps, msg, src) {
    // alert information
    var alertRisk = 1
    var alertConfidence = 3
    var alertTitle = 'addEventListener Find'
    var alertDesc = 'Potentional DOM XSS'
    var alertSolution = 'Investigate if addEventListener is vulnerable to DOM XSS'
    var cweId = 0
    var wascId = 0

    // lets build a regular expression that can find addEventListener
    // the regex must appear within /( and )/g
    var re = /(addEventListener)/g

    // we need to set the url variable to the request or we cant track the alert later
    var url = msg.getRequestHeader().getURI().toString()

    // lets check its not one of the files types that are never likely to contain stuff, like pngs and jpegs
    var contentType = msg.getResponseHeader().getHeader("Content-Type")
    var unwantedFileTypes = ['image/png', 'image/jpeg','image/gif','application/x-shockwave-flash','application/pdf', 'application/javascript']

    if (unwantedFileTypes.indexOf(""+contentType) >= 0) {
        // if we find one of the unwanted headers quit this scan, this saves time and reduces false positives
        return
	}
    // now lets run our regex against the body response
    var body = msg.getResponseBody().toString()
    if (re.test(body)) {
        re.lastIndex = 0 // After testing reset index
        // Look for IBAN addresses
        var foundIBAN = []
        var comm
        while (comm = re.exec(body)) {
            foundIBAN.push(comm[0])
        }
    // woohoo we found an IBAN lets make an alert for it
    ps.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDesc, url, '', '', foundIBAN.toString(), alertSolution, foundIBAN.toString(), cweId, wascId, msg)
    }
}
