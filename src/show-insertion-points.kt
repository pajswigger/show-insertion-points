package burp

import java.net.URL
import java.nio.ByteBuffer


class BurpExtender : IBurpExtender, IScannerCheck {
    lateinit var cb: IBurpExtenderCallbacks
    val insertionPointStore = HashMap<ByteBuffer, ArrayList<InsertionPoint>>()

    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        cb = callbacks
        callbacks.setExtensionName("Show Insertion Points")
        callbacks.registerScannerCheck(this)
    }

    override fun doActiveScan(baseRequestResponse: IHttpRequestResponse, insertionPoint: IScannerInsertionPoint): MutableList<IScanIssue> {
        baseRequestResponse.httpService

        // Fetch insertion points previously used for this base request
        val key = ByteBuffer.wrap(baseRequestResponse.request)
        if(!insertionPointStore.containsKey(key)) {
            insertionPointStore.put(key, arrayListOf<InsertionPoint>())
        }
        val insertionPoints = insertionPointStore.get(key)!!

        insertionPoints.add(InsertionPoint(insertionPoint))
        insertionPoints.sort()

        // Create an issue with all offsets highlighted
        val httpMessage = cb.applyMarkers(baseRequestResponse, insertionPoints.map { it.offsets }, null)
        val requestInfo = cb.helpers.analyzeRequest(baseRequestResponse.httpService, baseRequestResponse.request)
        return arrayListOf(ScanIssue(arrayOf(httpMessage), baseRequestResponse.httpService, requestInfo.url, insertionPoints))
    }

    override fun consolidateDuplicateIssues(existingIssue: IScanIssue, newIssue: IScanIssue): Int {
        // Remove exist issuing on consolidation - eventually leaving one issue that describes all insertion points
        return 1
    }

    override fun doPassiveScan(p0: IHttpRequestResponse?): MutableList<IScanIssue> {
        return arrayListOf()
    }
}


class InsertionPoint(val insertionPoint: IScannerInsertionPoint) : Comparable<InsertionPoint> {
    val offsets = insertionPoint.getPayloadOffsets(insertionPoint.baseValue.toByteArray(Charsets.ISO_8859_1))

    override fun compareTo(other: InsertionPoint): Int {
        return Integer.compare(offsets[0], other.offsets[0])
    }
}


class ScanIssue(val httpMessages_: Array<IHttpRequestResponse>,
                val httpService_: IHttpService,
                val url_: URL,
                val insertionPoints: List<InsertionPoint>) : IScanIssue {
    companion object {
        val typeLookup = hashMapOf<Byte,String>(
            0x00.toByte() to "INS_PARAM_URL",
            0x01.toByte() to "INS_PARAM_BODY",
            0x02.toByte() to "INS_PARAM_COOKIE",
            0x03.toByte() to "INS_PARAM_XML",
            0x04.toByte() to "INS_PARAM_XML_ATTR",
            0x05.toByte() to "INS_PARAM_MULTIPART_ATTR",
            0x06.toByte() to "INS_PARAM_JSON",
            0x07.toByte() to "INS_PARAM_AMF",
            0x20.toByte() to "INS_HEADER",
            0x21.toByte() to "INS_URL_PATH_FOLDER",
            0x22.toByte() to "INS_PARAM_NAME_URL",
            0x23.toByte() to "INS_PARAM_NAME_BODY",
            0x24.toByte() to "INS_ENTIRE_BODY",
            0x25.toByte() to "INS_URL_PATH_FILENAME",
            0x40.toByte() to "INS_USER_PROVIDED",
            0x41.toByte() to "INS_EXTENSION_PROVIDED",
            0x7f.toByte() to "INS_UNKNOWN"
        )
    }

    override fun getUrl(): URL {
        return url_
    }

    override fun getIssueName(): String {
        return "Insertion Points"
    }

    override fun getHttpMessages(): Array<IHttpRequestResponse> {
        return httpMessages_
    }

    override fun getHttpService(): IHttpService {
        return httpService_
    }

    override fun getIssueType(): Int {
        return 0x08000000 // Extension generated issue
    }

    override fun getRemediationBackground(): String {
        return ""
    }

    override fun getRemediationDetail(): String {
        return ""
    }

    override fun getConfidence(): String {
        return "Certain"
    }

    override fun getIssueBackground(): String {
        return ""
    }

    override fun getIssueDetail(): String {
        // TODO: More Kotlin approach
        val rc = StringBuilder();
        rc.append("<p>This finding shows the insertion points that the Scanner has used. There is no security impact.</p>")
        rc.append("<table>")
        for(ip in insertionPoints) {
            rc.append("<tr><td>${typeLookup.get(ip.insertionPoint.insertionPointType)}</td><td>${ip.insertionPoint.insertionPointName}</td></tr>")
        }
        rc.append("</table>")
        return rc.toString()
    }

    override fun getSeverity(): String {
        return "Information"
    }

}