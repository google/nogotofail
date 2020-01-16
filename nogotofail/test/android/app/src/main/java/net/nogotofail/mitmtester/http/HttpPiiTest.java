/*
 * Copyright 2014 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.nogotofail.mitmtester.http;

import net.nogotofail.mitmtester.BackgroundTestForHttpPii;

import android.content.Context;
import java.net.HttpURLConnection;
import java.net.URL;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicHeader;
import org.apache.http.params.HttpConnectionParams;
import org.apache.http.protocol.HTTP;
import org.json.JSONObject;

/*
 *  HttpPiiTest simulates the scenario where PII appears
 *  in the HTTP requests and responses.
 */
public class HttpPiiTest extends BackgroundTestForHttpPii {

    HttpURLConnection connection = null;
    URL url;

    protected HttpPiiTest(Context app_context) {
        super(app_context);
    }
    /**
     * Runs tests with PII in HTTP request and responses.
     */
    @Override
    protected void runTest() throws Exception {
        // Retrieve PII for testing
        FetchPIITestData();
        // Run PII in clear-text (HTTP) query string
        RunPiiQueryStringTest();
        // Run PII in clear-text (HTTP) headers
        RunPiiHeaderTest();
        // Run PII in clear-text (HTTP) message body
        RunPiiMessageBodyTest();
    }

    /**
     * Runs tests inserting PII in request query strings.
     */
    protected void RunPiiQueryStringTest() throws Exception {
        try {
            // Send request with PII identifier in query string
            url = new URL(HTTP_TARGET + "?google_ad_id=" + google_ad_id);
            connection = (HttpURLConnection) url.openConnection();
            connection.setConnectTimeout(CONNECTION_TIMEOUT);
            connection.setReadTimeout(CONNECTION_TIMEOUT);
            setProgressMessage("Issuing HTTP request with (clear-text) PII IDs in query string");
            setTestResult(connection.getResponseCode() + " " + connection.getResponseMessage());
            connection.disconnect();

            // Send request with PII location in query string
            url = new URL(HTTP_TARGET + "?longtitude=" + location_longitude +
                    "&latitude=" + location_latitude);
            connection = (HttpURLConnection) url.openConnection();
            connection.setConnectTimeout(CONNECTION_TIMEOUT);
            connection.setReadTimeout(CONNECTION_TIMEOUT);
            setProgressMessage("Issuing HTTP request with (clear-text) PII location in query string");
            setTestResult(connection.getResponseCode() + " " + connection.getResponseMessage());
            connection.disconnect();
        } catch (Exception e) {
            setTestResult("Error: " + " " + e.getMessage());
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    /**
     * Runs tests inserting PII in request headers.
     */
    protected void RunPiiHeaderTest() throws Exception {
        try {
            // Send request with PII identifier in HTTP header
            url = new URL(HTTP_TARGET);
            connection = (HttpURLConnection) url.openConnection();
            connection.setConnectTimeout(CONNECTION_TIMEOUT);
            connection.setReadTimeout(CONNECTION_TIMEOUT);
            connection.setRequestProperty("Header-Identifier", google_ad_id);
            setProgressMessage("Issuing HTTP request with (clear-text) PII ID in header");
            setTestResult(connection.getResponseCode() + " " + connection.getResponseMessage());
            connection.disconnect();

            // Send request with PII location in HTTP header
            url = new URL(HTTP_TARGET);
            connection = (HttpURLConnection) url.openConnection();
            connection.setConnectTimeout(CONNECTION_TIMEOUT);
            connection.setReadTimeout(CONNECTION_TIMEOUT);
            connection.setRequestProperty("Header-Longitude", location_longitude);
            connection.setRequestProperty("Header-Latitude", location_latitude);
            setProgressMessage("Issuing HTTP request with (clear-text) PII location in header");
            setTestResult(connection.getResponseCode() + " " + connection.getResponseMessage());
            connection.disconnect();
        }
        finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    /**
     * Runs tests inserting PII in request and response message bodies.
     */
    protected void RunPiiMessageBodyTest() throws Exception {
        HttpClient client = new DefaultHttpClient();
        HttpConnectionParams.setConnectionTimeout(client.getParams(), CONNECTION_TIMEOUT); //Timeout Limit
        HttpResponse response;
        JSONObject json_data;
        int response_code;
        String response_message;

        // Send PII identifier in HTTP POST request
        try {
            HttpPost post = new HttpPost(HTTP_TARGET);
            json_data = new JSONObject();
            json_data.put("google_ad_id", google_ad_id);
            StringEntity se = new StringEntity(json_data.toString());
            se.setContentType(new BasicHeader(HTTP.CONTENT_TYPE, "application/json"));
            post.setEntity(se);
            setProgressMessage("Issuing HTTP request with (clear-text) PII identifiers in " +
                    "message body");
            response = client.execute(post);

            // Checking response
            if(response!=null){
                //Get the data in the entity
                response_code = response.getStatusLine().getStatusCode();
                response_message = response.getStatusLine().getReasonPhrase();
                setTestResult(Integer.toString(response_code) + " " + response_message);
            }
        } catch(Exception e) {
            e.printStackTrace();
        }

        // Send PII location in HTTP POST request
        try {
            HttpPost post = new HttpPost(HTTP_TARGET);
            json_data = new JSONObject();
            json_data.put("location_longitude", location_longitude);
            json_data.put("location_latitude", location_latitude);
            StringEntity se = new StringEntity(json_data.toString());
            se.setContentType(new BasicHeader(HTTP.CONTENT_TYPE, "application/json"));
            post.setEntity(se);
            setProgressMessage("Issuing HTTP request with (clear-text) PII location in " +
                    "message body");
            response = client.execute(post);

            // Checking response
            if(response!=null){
                //Get the data in the entity
                response_code = response.getStatusLine().getStatusCode();
                response_message = response.getStatusLine().getReasonPhrase();
                setTestResult(Integer.toString(response_code) + " " + response_message);
            }
        } catch(Exception e) {
            e.printStackTrace();
        }
    }

}
