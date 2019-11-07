/**
 * Copyright (c) 2018. Department of Family Medicine, McMaster University. All Rights Reserved.
 * This software is published under the GPL GNU General Public License.
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * This software was written for the
 * Department of Family Medicine
 * McMaster University
 * Hamilton
 * Ontario, Canada
 */

package org.oscarehr.excelleris;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.net.ssl.SSLContext;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.http.Header;
import org.apache.http.NameValuePair;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.cookie.Cookie;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.cookie.BasicClientCookie;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.ssl.SSLContexts;

/**
 * -Dorg.apache.commons.logging.Log=org.apache.commons.logging.impl.SimpleLog
-Dorg.apache.commons.logging.simplelog.showdatetime=true
-Dorg.apache.commons.logging.simplelog.log.org.apache.http=DEBUG

 * @author Marc
 *
 */
public class Excelleris {
	
	static String cookieDomain = "api.ontest.excelleris.com";
	static BasicCookieStore cookieStore = new BasicCookieStore();
	
	public static void main(String[] args) {

		try {
			
			String certLocation = null;
			String storePass = null;
			String keyPass = null;
			String sslProtocol = null;
			String serverAddress = null;
			String username = null;
			String password = null;
			String outputDirectory = null;
			String pending = null;
			String host = null;
			String strVerbose = null;
			
			
			CommandLineParser parser = new DefaultParser();
			Options options = new Options();
			options.addOption("c", "cert", true, "JKS location. default is /opt/excelleris/excelleris.jks");
			options.addRequiredOption("l", "storepass", true, "JKS keystore password");
			options.addRequiredOption("k", "keypass", true, "Key password (for the key in the keystore)");
			options.addOption("a", "SSL protocol", true, "default is TLSv1");
			options.addOption("s", "BASE URL", true, "server url for Excelleris - default is https://api.ontest.excelleris.com");
			options.addRequiredOption("u", "username", true, "Username for Excelleris service");
			options.addRequiredOption("p", "password", true, "Password for Excelleris service");
			options.addOption("o", "outputDir", true, "Output directory for HL7 data. Default is /opt/excelleris/output");
			options.addOption("z", "pending", true, "Get Pending results true/false. Default is false");
			options.addOption("x", "host", true, "required for cookies. default is api.ontest.excelleris.com. in BC, use api.bctest.excelleris.com");
			options.addOption("h", "help", false, "What you are seeing now");
			options.addOption("v","verbose",true,"Show verbose output true/false. Default is false");
			try {
				CommandLine commandLine = parser.parse(options, args);

				certLocation = commandLine.getOptionValue("c", "/opt/excelleris/excelleris.jks");
				storePass = commandLine.getOptionValue("l");
				keyPass = commandLine.getOptionValue("k");
				sslProtocol = commandLine.getOptionValue("a", "TLSv1");
				serverAddress = commandLine.getOptionValue("s", "https://api.ontest.excelleris.com");

				username = commandLine.getOptionValue("u");
				password = commandLine.getOptionValue("p");

				outputDirectory = commandLine.getOptionValue("o","/opt/excelleris/output");
				
				pending = commandLine.getOptionValue("z","false");
				
				host = commandLine.getOptionValue("x","api.ontest.excelleris.com");
				
				strVerbose = commandLine.getOptionValue("v","false");
			
				cookieDomain = host;
				
				if (commandLine.hasOption("h")) {
					help(options);
					System.exit(0);
				}

			} catch (ParseException e) {
				System.err.println(e.getMessage());
				help(options);
				System.exit(1);
			}
			
			
			boolean verbose=false;
			if("true".equals(strVerbose)) {
				verbose=true;
			}

			//setup SSL
			SSLContext sslcontext = SSLContexts.custom()
					.loadKeyMaterial(new File(certLocation), storePass.toCharArray(), keyPass.toCharArray()).build();
			sslcontext.getDefaultSSLParameters().setNeedClientAuth(true);
			sslcontext.getDefaultSSLParameters().setWantClientAuth(true);
			
			SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslcontext, new String[] { sslProtocol },
					null, SSLConnectionSocketFactory.getDefaultHostnameVerifier());

			//login
			boolean login = login(serverAddress, cookieStore, sslsf, username, password,verbose);
			if(!login) {
				login = login(serverAddress, cookieStore, sslsf, username, password,verbose);
				if(!login) {
					System.err.println("Unable to login. Check your credentials");
					System.exit(1);
				}
			}
			
			
			if(verbose) {
				System.out.println("Logged in");
			}
			
			for(Cookie c: cookieStore.getCookies()) {
				if(verbose) {
					System.out.println("cookies");
					System.out.println("=================");
					System.out.println(c.getName() + "=" + c.getValue());
					System.out.println("=================");
				}
			}
			//make call for new data
			CloseableHttpClient	httpclient3 = HttpClients.custom().setDefaultCookieStore(cookieStore).setSSLSocketFactory(sslsf).build();
			HttpPost post4 = new HttpPost(serverAddress + "/launchpad/hl7pull.aspx");
			List<NameValuePair> params2 = new ArrayList<NameValuePair>();
			params2.add(new BasicNameValuePair("Page", "HL7"));
			params2.add(new BasicNameValuePair("Query", "NewRequests"));
			if("true".equalsIgnoreCase(pending)) {
				params2.add(new BasicNameValuePair("Pending", "Yes"));
			}
			post4.setEntity(new UrlEncodedFormEntity(params2));

			if(verbose) {
				System.out.println("Calling " + post4.getRequestLine());
			}
			CloseableHttpResponse response4 = httpclient3.execute(post4);
			if(verbose) {
				System.out.println(response4.getStatusLine());
				System.out.println(response4.getEntity().toString());
			}
			
			if(response4.getStatusLine().getStatusCode() == 302) {
				setupCookiesFromLastResponse(cookieStore, response4);
				
				httpclient3 = HttpClients.custom().setDefaultCookieStore(cookieStore).setSSLSocketFactory(sslsf).build();
				HttpGet post2 = new HttpGet(serverAddress + response4.getFirstHeader("Location").getValue());
				if(verbose) {
					System.out.println("Calling " + post2.getRequestLine());
				}
				
				response4 = httpclient3.execute(post2);
				
				if(verbose) {
					System.out.println(response4.getStatusLine());
					System.out.println(response4.getEntity().toString());
				}
				
				setupCookiesFromLastResponse(cookieStore, response4);
				
				httpclient3 = HttpClients.custom().setDefaultCookieStore(cookieStore).setSSLSocketFactory(sslsf).build();
				
				post4 = new HttpPost(serverAddress + "/launchpad/hl7pull.aspx");
				List<NameValuePair> params3 = new ArrayList<NameValuePair>();
				params3.add(new BasicNameValuePair("Page", "HL7"));
				params3.add(new BasicNameValuePair("Query", "NewRequests"));
				if("true".equalsIgnoreCase(pending)) {
					params3.add(new BasicNameValuePair("Pending", "Yes"));
				}
				post4.setEntity(new UrlEncodedFormEntity(params3));
			
				if(verbose) {
					System.out.println("Calling " + post4.getRequestLine());
				}
				response4 = httpclient3.execute(post4);
				
				if(verbose) {
					System.out.println(response4.getStatusLine());
					System.out.println(response4.getEntity().toString());
				}
				
				
			} else {
				
				
				//String total = parseResponse(response4);
				
				byte[] data = parseResponseToByteArray(response4);
				
			//	System.out.println(total);
				
				SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHMMss");
				String dt = formatter.format(new Date());
				
				writeToFile(data,outputDirectory +  File.separator + dt + ".hl7");
				
				acknowlege(serverAddress, cookieStore, sslsf,verbose);
			}
			
			logout(serverAddress, cookieStore, sslsf,verbose);
			
		} catch (Exception e) {
			e.printStackTrace();
		}

	}
	
	private static void help(Options options) {
		HelpFormatter hf = new HelpFormatter();
		hf.printHelp("Excelleris Downloader",options);
	}
	
	
	private static void writeToFile(byte[] data, String file) throws Exception {		
		FileUtils.writeByteArrayToFile(new File(file), data);
	}
	
	private static boolean logout(String serverAddress, BasicCookieStore cookieStore, SSLConnectionSocketFactory sslsf, boolean verbose) throws Exception {
		CloseableHttpClient httpclient = HttpClients.custom().setDefaultCookieStore(cookieStore).setSSLSocketFactory(sslsf).build();

		HttpPost post = new HttpPost(serverAddress + "/launchpad/hl7pull.aspx");
	
		List<NameValuePair> params = new ArrayList<NameValuePair>();
		params.add(new BasicNameValuePair("Logout", "Yes"));
		
		post.setEntity(new UrlEncodedFormEntity(params));

		if(verbose) {
			System.out.println("Calling " + post.getRequestLine());
		}
	
		CloseableHttpResponse response = httpclient.execute(post);
		setupCookiesFromLastResponse(cookieStore,response);
		
		if(response.getStatusLine().getStatusCode() == 302) {
			if(verbose) {
				System.out.println("REDIRECT TO " + response.getFirstHeader("Location").getValue());
			}
			return false;
		} else if(response.getStatusLine().getStatusCode() == 200) {
			String result = parseResponse(response);
			if(verbose) {
				System.out.println("log out went through");
				System.out.println(result);
			}
			return true;
		}
		
		if(verbose) {
			System.out.println("got an unknown response");
		}
		return false;
	}

	private static boolean acknowlege(String serverAddress, BasicCookieStore cookieStore, SSLConnectionSocketFactory sslsf, boolean verbose) throws Exception {
		CloseableHttpClient httpclient = HttpClients.custom().setDefaultCookieStore(cookieStore).setSSLSocketFactory(sslsf).build();

		HttpPost post = new HttpPost(serverAddress + "/launchpad/hl7pull.aspx");
	
		List<NameValuePair> params = new ArrayList<NameValuePair>();
		params.add(new BasicNameValuePair("Page", "HL7"));
		params.add(new BasicNameValuePair("ACK", "Positive"));
		
		post.setEntity(new UrlEncodedFormEntity(params));

		if(verbose) {
			System.out.println("Calling " + post.getRequestLine());
		}
	
		CloseableHttpResponse response = httpclient.execute(post);
		setupCookiesFromLastResponse(cookieStore,response);
		
		if(response.getStatusLine().getStatusCode() == 302) {
			if(verbose) {
				System.out.println("REDIRECT TO " + response.getFirstHeader("Location").getValue());
			}
			return false;
		} else if(response.getStatusLine().getStatusCode() == 200) {
			setupCookiesFromLastResponse(cookieStore,response);
			String result = parseResponse(response);
			if(verbose) {
				System.out.println("ack went through");
				System.out.println(result);
			}
			return true;
		}
		if(verbose) {
			System.out.println("got an unknown response");
		}
		return false;
	}
	
	private static boolean login(String serverAddress, BasicCookieStore cookieStore, SSLConnectionSocketFactory sslsf, String username, String password, boolean verbose) throws Exception {
		
		RequestConfig defaultRequestConfig = RequestConfig.custom()
		        .setConnectTimeout(30000)
		        .setSocketTimeout(30000)
		        .setConnectionRequestTimeout(120000)
		        .build();
		
		CloseableHttpClient httpclient = HttpClients.custom().setDefaultRequestConfig(defaultRequestConfig).setDefaultCookieStore(cookieStore).setSSLSocketFactory(sslsf).build();

		HttpPost post = new HttpPost(serverAddress + "/launchpad/hl7pull.aspx");
	
		List<NameValuePair> params = new ArrayList<NameValuePair>();
		params.add(new BasicNameValuePair("Page", "Login"));
		params.add(new BasicNameValuePair("Mode", "Silent"));
		params.add(new BasicNameValuePair("UserID", username));
		params.add(new BasicNameValuePair("Password", password));
		post.setEntity(new UrlEncodedFormEntity(params));

		post.setHeader("User-Agent", "Mozilla/5.0 (Windows NT 6.2; OSCAR;15) Gecko/20100101 Firefox/32.0");
		if(verbose) {
			System.out.println("Calling " + post.getRequestLine());
		}
	 
		CloseableHttpResponse response = httpclient.execute(post);
		
		if(response.getStatusLine().getStatusCode() == 302) {
			if(verbose) {
				System.out.println("REDIRECT TO " + response.getFirstHeader("Location").getValue());
			}
			setupCookiesFromLastResponse(cookieStore,response);
			
			CloseableHttpClient httpclient2 = HttpClients.custom().setDefaultCookieStore(cookieStore).setSSLSocketFactory(sslsf).build();
			HttpGet post2 = new HttpGet(serverAddress + response.getFirstHeader("Location").getValue());
			if(verbose) {
				System.out.println("Calling " + post2.getRequestLine());
			}
			CloseableHttpResponse response2 = httpclient2.execute(post2);
			if(response2.getStatusLine().getStatusCode() == 200) {
				setupCookiesFromLastResponse(cookieStore, response2);
				return false;
			}
			
		} else if(response.getStatusLine().getStatusCode() == 200) {
			setupCookiesFromLastResponse(cookieStore,response);
			String result = parseResponse(response);
			if(verbose) {
				System.out.println("log in went through");
				System.out.println(result);
			}
			if(result == null) {
				return false;
			}
			if("<Authentication>AccessGranted</Authentication>".equals(result)) {
				return true;
			}
			return false;
		}
		
		if(verbose) {
			System.out.println("got an unknown response");
		}
		return false;
	}

	static String parseResponse(CloseableHttpResponse response) {
		
		BufferedReader r = null;
		
		try {
			r = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
	
			StringBuilder total = new StringBuilder();
	
			String line = null;
	
			while ((line = r.readLine()) != null) {
			   total.append(line);
			}
			
			return total.toString();
		} catch(Exception e) {
			System.err.println("Error - " + e.getMessage());
		} finally {
			try {
				r.close();
			}catch(IOException e) {
				
			}
		}
		
		return null;
	}
	
	static byte[] parseResponseToByteArray(CloseableHttpResponse response) {
		try {
			byte[] bytes = IOUtils.toByteArray(response.getEntity().getContent());
			return bytes;
		}catch(IOException e) {
			System.err.println("Error - " + e.getMessage());
		}
		
		return null;
	}
	
	static void setupCookiesFromLastResponse(BasicCookieStore cookieStore, CloseableHttpResponse response) {
		Header[] hList = response.getAllHeaders();
		for(int x=0;x<hList.length;x++) {
			if(hList[x].getName().equals("Set-Cookie")) {
				String vals[] = hList[x].getValue().split("=");
				BasicClientCookie cookie = new BasicClientCookie(vals[0],vals[1].substring(0, vals[1].indexOf(";")));
				cookie.setDomain(cookieDomain);
				cookie.setPath("/");
				cookie.setSecure(true);
				if(!cookie.getValue().equals("deleted")) {
					cookieStore.addCookie(cookie);
				}
			}

		}
	}
}
