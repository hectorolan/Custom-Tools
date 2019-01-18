<%@ WebHandler Language = "C#" Class="RedfishProxyHandler" Debug="true" %>

using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Web;

/*
* Reference
* https://gist.github.com/anth-3/6169292
*/

public class RedfishProxyHandler : IHttpHandler
{
    public RedfishProxyHandler() { }

    /**
    * <summary>
    * <c>ProcessRequest</c> overrides the <see cref="IHttpHandler.ProcessRequest"/> method to process a 
    * request.
    * </summary>
    * <remarks>
    * The <c>ProcessRequest</c> method enables the processing of HTTP Web requests on the passed 
    * <see cref="HttpContext"/> so that it can be analyzed, parsed, and processed for the proxy to 
    * forward the request.
    * </remarks>
    * <param name="Context">The <see cref="HttpContext"/> that needs to be processed for proxying.</param>
    * <seealso cref="IHttpHandler.ProcessRequest"/>
    */
    public void ProcessRequest(HttpContext Context)
    {

        /* Create variables to hold the request and response. */
        HttpRequest Request = Context.Request;
        HttpResponse Response = Context.Response;
        string URI = null;

        /* Attempt to get the URI the proxy is to pass along or fail. */
        try
        {
            URI = Request.Url.Query.Substring(1);
        }
        catch (Exception ex)
        {
            Response.StatusCode = 500;
            Response.StatusDescription = "Parameter Missing";
            Response.Write("In order to work follow the URL with '?https://[iloIP]/redfish/v1/...'");
            Response.End();
            return;
        }

        /* Create an HttpWebRequest to send the URI on and process results. */
        System.Net.HttpWebRequest ProxyRequest = (System.Net.HttpWebRequest)System.Net.HttpWebRequest.Create(URI);

        /* Set the appropriate values to the request methods. */
        ProxyRequest.Method = Request.HttpMethod;
        ProxyRequest.ServicePoint.Expect100Continue = false;
        ProxyRequest.Referer = Request.Headers["referer"];

        this.SetAuthorization(ProxyRequest, Request);

        //Response.Write(this.GetStateToPrint(Request, Response));

        /* Set the body of ProxyRequest for POST requests to the proxy. */
        if (Request.InputStream.Length > 0)
        {
            /* 
                * Since we are using the same request method as the original request, and that is 
                * a POST, the values to send on in the new request must be grabbed from the 
                * original POSTed request.
                */
            byte[] Bytes = new byte[Request.InputStream.Length];

            Request.InputStream.Read(Bytes, 0, (int)Request.InputStream.Length);

            ProxyRequest.ContentLength = Bytes.Length;

            string ContentType = Request.ContentType;

            if (String.IsNullOrEmpty(ContentType))
            {
                ProxyRequest.ContentType = "application/x-www-form-urlencoded";
            }
            else
            {
                ProxyRequest.ContentType = ContentType;
            }

            using (Stream OutputStream = ProxyRequest.GetRequestStream())
            {
                OutputStream.Write(Bytes, 0, Bytes.Length);
            }
        }
        else
        {
            /*
                * When the original request is a GET, things are much easier, as we need only to 
                * pass the URI we collected earlier which will still have any parameters 
                * associated with the request attached to it.
                */
            ProxyRequest.Method = "GET";
        }

        // This line is necesary to do not validate the certificate. If not used it will fail with error 500.
        System.Net.ServicePointManager.ServerCertificateValidationCallback = ((sender, certificate, chain, sslPolicyErrors) => true);

        System.Net.WebResponse ServerResponse = null;

        /* Send the proxy request to the remote server or fail. */
        try
        {
            ServerResponse = ProxyRequest.GetResponse();
        }
        catch (System.Net.WebException WebEx)
        {
            Response.StatusDescription = WebEx.Status.ToString();
            //Response.Write(WebEx.Response);
            Response.Write(WebEx.ToString());
            Response.End();
            return;
        }

        /* Set up the response to the client if there is one to set up. */
        if (ServerResponse != null)
        {
            Response.ContentType = ServerResponse.ContentType;
            //if (string.IsNullOrEmpty(ServerResponse.Headers["x-auth-token"]))
            //{
            //    Response.Headers.Add("x-auth-token", ServerResponse.Headers["x-auth-token"]);
            //}
            using (Stream ByteStream = ServerResponse.GetResponseStream())
            {
                /* What is the response type? */
                if (ServerResponse.ContentType.Contains("text") ||
                        ServerResponse.ContentType.Contains("json") ||
                        ServerResponse.ContentType.Contains("xml"))
                {
                    /* These "text" types are easy to handle. */
                    using (StreamReader Reader = new StreamReader(ByteStream))
                    {
                        string ResponseString = Reader.ReadToEnd();

                        /* 
                            * Tell the client not to cache the response since it 
                            * could easily be dynamic, and we do not want to mess
                            * that up!
                            */
                        Response.CacheControl = "no-cache";
                        Response.Write(ResponseString);
                    }
                }
                else
                {
                    /* 
                        * Handle binary responses (image, layer file, other binary 
                        * files) differently than text.
                        */
                    BinaryReader BinReader = new BinaryReader(ByteStream);

                    byte[] BinaryOutputs = BinReader.ReadBytes((int)ServerResponse.ContentLength);

                    BinReader.Close();

                    /* 
                        * Tell the client not to cache the response since it could 
                        * easily be dynamic, and we do not want to mess that up!
                        */
                    Response.CacheControl = "no-cache";
                    /*
                        * Send the binary response to the client.
                        * (Note: if large images/files are sent, we could modify this to 
                        * send back in chunks instead...something to think about for 
                        * future.)
                        */
                    Response.OutputStream.Write(BinaryOutputs, 0, BinaryOutputs.Length);
                }
                ServerResponse.Close();
            }
        }
        Response.End();
    }

    /**
    * <summary>
    * <c>IsReusable</c> overrides the <see cref="IHttpHandler.IsReusable"/> property to indicate if 
    * another request can use this instance.
    * </summary>
    * <remarks>
    * <c>IsReusable</c> gets a value indicating whether or not another request can use the 
    * <see cref="IHttpHandler"/> instance.
    * </remarks>
    */
    public bool IsReusable
    {
        get { return false; }
    }

    public void SetAuthorization(System.Net.HttpWebRequest proxyRequest, HttpRequest originalRequest)
    {
        string authHeader = originalRequest.Headers["Authorization"];

        //if (string.IsNullOrEmpty(originalRequest.Headers["x-auth-token"]+ ""))
        //{
        //   proxyRequest.Headers.Add("x-auth-token", originalRequest.Headers["x-auth-token"]);
        //}
        if (authHeader != null && authHeader.StartsWith("Basic")) {
            string encodedUsernamePassword = authHeader.Substring("Basic ".Length).Trim();
            Encoding encoding = Encoding.GetEncoding("iso-8859-1");
            string usernamePassword = encoding.GetString(Convert.FromBase64String(encodedUsernamePassword));

            int seperatorIndex = usernamePassword.IndexOf(':');

            var username = usernamePassword.Substring(0, seperatorIndex);
            var password = usernamePassword.Substring(seperatorIndex + 1);

            String encoded = System.Convert.ToBase64String(System.Text.Encoding.GetEncoding("ISO-8859-1").GetBytes(username + ":" + password));
            proxyRequest.Headers.Add("Authorization", "Basic " + encoded);

        } else {
            //Handle what happens if that isn't the case
            //throw new Exception("The authorization header is either empty or isn't Basic.");
        }
    }

    public string GetStateToPrint(HttpRequest req, HttpResponse res)
    {
        StringBuilder sb = new StringBuilder();
        sb.AppendLine("Request");
        foreach (string key in req.Headers)
        {
            sb.AppendLine(string.Format("{0} : {1}", key, req.Headers[key]));
        }
        sb.AppendLine(string.Format("{0} : {1}", "ContentType", req.ContentType));
        sb.AppendLine(string.Format("{0} : {1}", "Action", req.HttpMethod));
        return sb.ToString();
    }

    public string GetStateToPrint( System.Net.HttpWebRequest req)
    {
        StringBuilder sb = new StringBuilder();
        sb.AppendLine("ProxyRequest");
        foreach (string key in req.Headers)
        {
            sb.AppendLine(string.Format("{0} : {1}", key, req.Headers[key]));
        }
        sb.AppendLine(string.Format("{0} : {1}", "ContentType", req.ContentType));
        sb.AppendLine(string.Format("{0} : {1}", "Action", req.Method));
        return sb.ToString();
    }
}
