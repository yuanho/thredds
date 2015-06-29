/*
 * Copyright (c) 1998 - 2012. University Corporation for Atmospheric Research/Unidata
 * Portions of this software were developed by the Unidata Program at the
 * University Corporation for Atmospheric Research.
 *
 * Access and use of this software shall impose the following obligations
 * and understandings on the user. The user is granted the right, without
 * any fee or cost, to use, copy, modify, alter, enhance and distribute
 * this software, and any derivative works thereof, and its supporting
 * documentation for any purpose whatsoever, provided that this entire
 * notice appears in all copies of the software, derivative works and
 * supporting documentation.  Further, UCAR requests that the user credit
 * UCAR/Unidata in any publications that result from the use of this
 * software or in any product that includes this software. The names UCAR
 * and/or Unidata, however, may not be used in any advertising or publicity
 * to endorse or promote any products or commercial entity unless specific
 * written permission is obtained from UCAR/Unidata. The user also
 * understands that UCAR/Unidata is not obligated to provide the user with
 * any support, consulting, training or assistance of any kind with regard
 * to the use, operation and performance of this software nor to provide
 * the user with any updates, revisions, new versions or "bug fixes."
 *
 * THIS SOFTWARE IS PROVIDED BY UCAR/UNIDATA "AS IS" AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL UCAR/UNIDATA BE LIABLE FOR ANY SPECIAL,
 * INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE ACCESS, USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package ucar.nc2.util.net;

import org.apache.http.HttpEntity;
import org.junit.Test;
import ucar.httpservices.HTTPException;
import ucar.httpservices.HTTPFactory;
import ucar.httpservices.HTTPFormBuilder;
import ucar.httpservices.HTTPMethod;
import ucar.nc2.util.UnitTestCommon;

/**
 * Test HttpFormBuilder
 */

public class TestFormBuilder extends UnitTestCommon
{

    //////////////////////////////////////////////////
    // Constants

    static protected final String TESTURL = "http://echo.httpkit.com";

    static protected final String STDBOUNDARY = "XXXXXXXXXXXXXXXXXXXX";

    // Field values to use
    static final String DESCRIPTIONENTRY = "TestFormBuilder";
    static final String NAMEENTRY = "Mr. Jones";
    static final String EMAILENTRY = "idv@ucar.edu";
    static final String ORGENTRY = "UCAR";
    static final String SUBJECTENTRY = "hello";
    static final String SOFTWAREPACKAGEENTRY = "IDV";
    static final String VERSIONENTRY = "1.0.1";
    static final String HARDWAREENTRY = "Windows";
    static final String EXTRATEXT = "extra";
    static final String BUNDLETEXT = "bundle";

    //////////////////////////////////////////////////
    // Instance Variables

    int passcount = 0;
    int xfailcount = 0;
    int failcount = 0;
    boolean verbose = true;
    boolean pass = false;

    //////////////////////////////////////////////////
    // Constructor(s)

    public TestFormBuilder()
    {
        setTitle("HTTPFormBuilder test(s)");
        setSystemProperties();
    }

    @Test
    public void
    testSimple()
            throws Exception
    {
        pass = true;
        try {
            HTTPFormBuilder builder = buildForm(false);
            HttpEntity content = builder.build();
            try (HTTPMethod postMethod = HTTPFactory.Post(TESTURL)) {
                postMethod.setRequestContent(content);
                postMethod.execute();
                int code = postMethod.getStatusCode();
                String body = postMethod.getResponseAsString();
                if(code != 200) {
                    System.err.println("Bad return code: " + code);
                    pass = false;
                }
                body = fixContentLength(body);
                if(prop_visual)
                    visual(TESTURL, body);
                if(pass) {
                    String diffs = compare("TestFormBuilder.simple", expectedSimple, body);
                    if(diffs != null) {
                        System.err.println(diffs);
                        pass = false;
                    }
                }
            }
        } catch (Exception exc) {
            exc.printStackTrace();
            pass = false;
        }
        assertTrue("TestFormBuilder.simple: failed", pass);
    }

    @Test
    public void
    testMultiPart()
            throws Exception
    {
        pass = true;
        try {
            HTTPFormBuilder builder = buildForm(true);
            HttpEntity content = builder.build();
            try (HTTPMethod postMethod = HTTPFactory.Post(TESTURL)) {
                postMethod.setRequestContent(content);
                postMethod.execute();
                int code = postMethod.getStatusCode();
                String body = postMethod.getResponseAsString();
                if(code != 200) {
                    System.err.println("Bad return code: " + code);
                    pass = false;
                }
                body = fixContentLength(body);
                if(prop_visual)
                    visual(TESTURL, body);
                if(pass) {
                    body = fixBoundary(body);
                    String diffs = compare("TestFormBuilder", expectedMultipart, body);
                    if(diffs != null) {
                        System.err.println(diffs);
                        pass = false;
                    }
                }
            }
        } catch (Exception exc) {
            exc.printStackTrace();
            pass = false;
        }
        assertTrue("TestFormBuilder.multipart: failed", pass);
    }

    protected HTTPFormBuilder buildForm(boolean multipart)
            throws HTTPException
    {
        HTTPFormBuilder builder = new HTTPFormBuilder();

        StringBuffer javaInfo = new StringBuffer();
        javaInfo.append("Java: home: " + System.getProperty("java.home"));
        javaInfo.append(" version: " + System.getProperty("java.version"));

        builder.add("fullName", NAMEENTRY);
        builder.add("emailAddress", EMAILENTRY);
        builder.add("organization", ORGENTRY);
        builder.add("subject", SUBJECTENTRY);
        builder.add("description", DESCRIPTIONENTRY);
        builder.add("softwarePackage", SOFTWAREPACKAGEENTRY);
        builder.add("packageVersion", VERSIONENTRY);
        builder.add("os", System.getProperty("os.name"));
        builder.add("hardware", HARDWAREENTRY);

        if(multipart) {
            builder.add("attachmentOne", EXTRATEXT.getBytes(HTTPFormBuilder.ASCII), "extra.html");
            builder.add("attachmentTwo", BUNDLETEXT.getBytes(HTTPFormBuilder.ASCII), "bundle.xidv");
            builder.add("attachmentThree", new byte[]{1, 2, 0}, "arbfile");
        }
        return builder;
    }

    protected String fixBoundary(String json)
    {
        String[] lines = json.split("\n");
        String boundary = null;
        for(int i = 0; i < lines.length; i++) {
            String line = lines[i];
            if(line.startsWith("  \"body\":")) {
                boundary = locateBoundary(line);
                break;
            }
        }
        if(boundary != null)
            json = json.replace(boundary, STDBOUNDARY);
        return json;
    }

    protected String locateBoundary(String line)
    {
        line = line.replace("\\r", "");
        line = line.replace("\\n", "\n");
        String[] lines = line.split("\n");
        int pos1 = lines[0].indexOf("--");
        if(pos1 < 0) return null;
        String boundary = lines[0].substring(pos1 + 2, lines[0].length());
        return boundary;
    }

    protected String fixContentLength(String json)
    {
        String[] lines = json.split("\n");
        StringBuilder buf = new StringBuilder();
        for(int i = 0; i < lines.length; i++) {
            String line = lines[i];
            if(!line.startsWith("    \"content-length\":")) {
                buf.append(line);
                buf.append("\n");
            }
        }
        return buf.toString();
    }


    static final String expectedSimple =
            "{\n"
                    + "  \"method\": \"POST\",\n"
                    + "  \"uri\": \"/\",\n"
                    + "  \"path\": {\n"
                    + "    \"name\": \"/\",\n"
                    + "    \"query\": \"\",\n"
                    + "    \"params\": {}\n"
                    + "  },\n"
                    + "  \"headers\": {\n"
                    + "    \"x-forwarded-for\": \"128.117.140.39\",\n"
                    + "    \"host\": \"echo.httpkit.com\",\n"
                    + "    \"user-agent\": \"/NetcdfJava/HttpClient4.3\",\n"
                    + "    \"content-type\": \"application/x-www-form-urlencoded\"\n"
                    + "  },\n"
                    + "  \"body\": \"os=Windows+7&organization=UCAR&hardware=Windows&packageVersion=1.0.1&softwarePackage=IDV&description=TestFormBuilder&subject=hello&emailAddress=idv%40ucar.edu&fullName=Mr.+Jones\",\n"
                    + "  \"ip\": \"127.0.0.1\",\n"
                    + "  \"powered-by\": \"http://httpkit.com\",\n"
                    + "  \"docs\": \"http://httpkit.com/echo\"\n"
                    + "}\n";

    static final String expectedMultipart =
            "{\n"
                    + "  \"method\": \"POST\",\n"
                    + "  \"uri\": \"/\",\n"
                    + "  \"path\": {\n"
                    + "    \"name\": \"/\",\n"
                    + "    \"query\": \"\",\n"
                    + "    \"params\": {}\n"
                    + "  },\n"
                    + "  \"headers\": {\n"
                    + "    \"x-forwarded-for\": \"128.117.140.39\",\n"
                    + "    \"host\": \"echo.httpkit.com\",\n"
                    + "    \"user-agent\": \"/NetcdfJava/HttpClient4.3\",\n"
                    + "    \"content-type\": \"multipart/form-data; boundary=XXXXXXXXXXXXXXXXXXXX; charset=UTF-8\"\n"
                    + "  },\n"
                    + "  \"body\": \"--XXXXXXXXXXXXXXXXXXXX\\r\\nContent-Disposition: form-data; name=\\\"os\\\"\\r\\n\\r\\nWindows 7\\r\\n--XXXXXXXXXXXXXXXXXXXX\\r\\nContent-Disposition: form-data; name=\\\"organization\\\"\\r\\n\\r\\nUCAR\\r\\n--XXXXXXXXXXXXXXXXXXXX\\r\\nContent-Disposition: form-data; name=\\\"attachmentOne\\\"; filename=\\\"extra.html\\\"\\r\\nContent-Type: application/octet-stream\\r\\n\\r\\nextra\\r\\n--XXXXXXXXXXXXXXXXXXXX\\r\\nContent-Disposition: form-data; name=\\\"hardware\\\"\\r\\n\\r\\nWindows\\r\\n--XXXXXXXXXXXXXXXXXXXX\\r\\nContent-Disposition: form-data; name=\\\"packageVersion\\\"\\r\\n\\r\\n1.0.1\\r\\n--XXXXXXXXXXXXXXXXXXXX\\r\\nContent-Disposition: form-data; name=\\\"softwarePackage\\\"\\r\\n\\r\\nIDV\\r\\n--XXXXXXXXXXXXXXXXXXXX\\r\\nContent-Disposition: form-data; name=\\\"attachmentThree\\\"; filename=\\\"arbfile\\\"\\r\\nContent-Type: application/octet-stream\\r\\n\\r\\n\\u0001\\u0002\\u0000\\r\\n--XXXXXXXXXXXXXXXXXXXX\\r\\nContent-Disposition: form-data; name=\\\"attachmentTwo\\\"; filename=\\\"bundle.xidv\\\"\\r\\nContent-Type: application/octet-stream\\r\\n\\r\\nbundle\\r\\n--XXXXXXXXXXXXXXXXXXXX\\r\\nContent-Disposition: form-data; name=\\\"description\\\"\\r\\n\\r\\nTestFormBuilder\\r\\n--XXXXXXXXXXXXXXXXXXXX\\r\\nContent-Disposition: form-data; name=\\\"subject\\\"\\r\\n\\r\\nhello\\r\\n--XXXXXXXXXXXXXXXXXXXX\\r\\nContent-Disposition: form-data; name=\\\"emailAddress\\\"\\r\\n\\r\\nidv@ucar.edu\\r\\n--XXXXXXXXXXXXXXXXXXXX\\r\\nContent-Disposition: form-data; name=\\\"fullName\\\"\\r\\n\\r\\nMr. Jones\\r\\n--XXXXXXXXXXXXXXXXXXXX--\\r\\n\",\n"
                    + "  \"ip\": \"127.0.0.1\",\n"
                    + "  \"powered-by\": \"http://httpkit.com\",\n"
                    + "  \"docs\": \"http://httpkit.com/echo\"\n"
                    + "}\n";
}
