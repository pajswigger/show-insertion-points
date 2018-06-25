package burp

import java.net.URL
import java.nio.ByteBuffer


class BurpExtender : IBurpExtender, IScannerCheck, IScannerInsertionPointProvider{
    lateinit var cb: IBurpExtenderCallbacks
    val insertionPointStore = HashMap<ByteBuffer, InsertionPointList>()

    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        cb = callbacks
        callbacks.setExtensionName("Show Insertion Points")
        callbacks.registerScannerCheck(this)
        callbacks.registerScannerInsertionPointProvider(this)
    }

    override fun getInsertionPoints(baseRequestResponse: IHttpRequestResponse): MutableList<IScannerInsertionPoint> {
        val key = ByteBuffer.wrap(baseRequestResponse.request)
        insertionPointStore.remove(key)
        return mutableListOf<IScannerInsertionPoint>()
    }

    override fun doActiveScan(baseRequestResponse: IHttpRequestResponse, insertionPoint: IScannerInsertionPoint): MutableList<IScanIssue> {
        // Fetch insertion points previously used for this base request
        val key = ByteBuffer.wrap(baseRequestResponse.request)
        var insertionPoints = insertionPointStore[key]
        if(insertionPoints == null) {
            insertionPoints = InsertionPointList()
            insertionPointStore[key] = insertionPoints
        }

        insertionPoints.add(InsertionPoint(insertionPoint))
        insertionPoints.sort()

        // Create an issue with all offsets highlighted
        val httpMessage = cb.applyMarkers(baseRequestResponse, insertionPoints.getOffsets(), null)
        val requestInfo = cb.helpers.analyzeRequest(baseRequestResponse.httpService, baseRequestResponse.request)
        return arrayListOf(ScanIssue(arrayOf(httpMessage), baseRequestResponse.httpService, requestInfo.url, insertionPoints))
    }

    override fun consolidateDuplicateIssues(existingIssue: IScanIssue, newIssue: IScanIssue): Int {
        // Remove existing issue on consolidation - eventually leaving one issue that describes all insertion points
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


class InsertionPointList : ArrayList<InsertionPoint>() {
    fun getOffsets(): List<IntArray> {
        val offsetsList = arrayListOf<IntArray>()
        for(insertionPoint in this) {
            if(offsetsList.isEmpty()) {
                offsetsList.add(insertionPoint.offsets)
                continue
            }
            val prevOffsets = offsetsList[offsetsList.size - 1]
            // TODO: check for fencepost errors
            if(insertionPoint.offsets[0] > prevOffsets[1]) {
                offsetsList.add(insertionPoint.offsets)
            }
        }
        return offsetsList
    }
}


class ScanIssue(val httpMessages_: Array<IHttpRequestResponse>,
                val httpService_: IHttpService,
                val url_: URL,
                val insertionPoints: List<InsertionPoint>) : IScanIssue {
    companion object {
        val typeLookup = mapOf<Byte,String>(
            0x00.toByte() to "PARAM_URL",
            0x01.toByte() to "PARAM_BODY",
            0x02.toByte() to "PARAM_COOKIE",
            0x03.toByte() to "PARAM_XML",
            0x04.toByte() to "PARAM_XML_ATTR",
            0x05.toByte() to "PARAM_MULTIPART_ATTR",
            0x06.toByte() to "PARAM_JSON",
            0x07.toByte() to "PARAM_AMF",
            0x20.toByte() to "HEADER",
            0x21.toByte() to "URL_PATH_FOLDER",
            0x22.toByte() to "PARAM_NAME_URL",
            0x23.toByte() to "PARAM_NAME_BODY",
            0x24.toByte() to "ENTIRE_BODY",
            0x25.toByte() to "URL_PATH_FILENAME",
            0x40.toByte() to "USER_PROVIDED",
            0x41.toByte() to "EXTENSION_PROVIDED",
            0x7f.toByte() to "UNKNOWN"
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
        val rc = StringBuilder();
        rc.append("<p>This finding shows the insertion points that the Scanner has used. There is no security impact.</p>")
        rc.append("<table>")
        for(ip in insertionPoints) {
            rc.append("<tr><td>${typeLookup.get(ip.insertionPoint.insertionPointType)}</td><td>${escapeXss(ip.insertionPoint.insertionPointName)}</td><td>${ip.offsets[0]}</td><td>${ip.offsets[1]}</td></tr>")
        }
        rc.append("</table>")
        return rc.toString()
    }

    override fun getSeverity(): String {
        return "Information"
    }

    fun escapeXss(input: String): String {
        return input.replace("<", "&lt;").replace("&", "&amp;")
    }

}