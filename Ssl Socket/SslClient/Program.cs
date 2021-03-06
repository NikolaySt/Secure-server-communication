using System;
using System.Collections;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.Threading;

namespace SslClient
{
	public class SslTcpClient
	{
		static byte[] ReadFile(string fileName)
		{
			using (var file = new FileStream(fileName, FileMode.Open, FileAccess.Read))
			{
				int size = (int)file.Length;
				byte[] data = new byte[size];
				size = file.Read(data, 0, size);
				file.Close();
				return data;
			}
		}

		private static Hashtable certificateErrors = new Hashtable();

		// The following method is invoked by the RemoteCertificateValidationDelegate.
		public static bool ValidateServerCertificate(
			  object sender,
			  X509Certificate certificate,
			  X509Chain chain,
			  SslPolicyErrors sslPolicyErrors)
		{
			return true;

			if (sslPolicyErrors == SslPolicyErrors.None)
				return true;

			Console.WriteLine("Certificate error: {0}", sslPolicyErrors);

			// Do not allow this client to communicate with unauthenticated servers.
			return false;
		}

		public static X509Certificate LocalCertificateSelectionCallback(
			object sender,
			string targetHost,
			X509CertificateCollection localCertificates,
			X509Certificate remoteCertificate,
			string[] acceptableIssuers)
		{
			var basePath = AppDomain.CurrentDomain.BaseDirectory;
			var certificate = basePath + "\\dbclient.pfx";
			var clientCertificate = new X509Certificate2(certificate, "test");
			return clientCertificate;
		}
		static void ProcessDnsInformation(IAsyncResult result)
		{
			if (result.AsyncState is tracessl)
			{
				Console.WriteLine($"AsyncState: {((tracessl)result.AsyncState).value}");
			}
		}
		public struct tracessl
		{
			public int value { get; set; }
		}

		public static void RunClient(string machineName, string serverName)
		{
			IPEndPoint remoteEndpoint = new IPEndPoint(IPAddress.Parse(machineName), 4301);
			var socket = new Socket(remoteEndpoint.AddressFamily, SocketType.Stream, ProtocolType.IP);
			
			IPEndPoint clientEndpoint = new IPEndPoint(IPAddress.Parse(machineName), 4301);
			//socket.Bind(remoteEndpoint);
			socket.BeginConnect(remoteEndpoint, (result) =>
			{
				//if (!socket.Connected) return;
				socket.EndConnect(result);
				Console.WriteLine("{0}: Client at {1} connected to the server at {2}.", DateTime.Now, clientEndpoint, remoteEndpoint);
				Process(new NetworkStream(socket));
			}, new tracessl() { value = 10009 });
		}
		public static void Process(NetworkStream client)
		{
			Console.WriteLine("Client connected.");
			// Create an SSL stream that will close the client's stream.
			SslStream sslStream = new SslStream(
				client,
				false,
				new RemoteCertificateValidationCallback(ValidateServerCertificate),
				new LocalCertificateSelectionCallback(LocalCertificateSelectionCallback),
				EncryptionPolicy.RequireEncryption
				);
			// The server name must match the name on the server certificate.
			try
			{
				//sslStream.AuthenticateAsClient(serverName);
				var basePath = AppDomain.CurrentDomain.BaseDirectory;
				var certificate = basePath + "\\dbclient.pfx";
				var clientCertificate = new X509Certificate2(certificate, "test");
				sslStream.AuthenticateAsClient(
					"Nikolay", 
					new X509CertificateCollection() { clientCertificate }, 
					SslProtocols.Ssl3, 
					false);

				//var result = sslStream.BeginAuthenticateAsClient(
				//	"Nikolay",
				//	new X509CertificateCollection() { clientCertificate },
				//	SslProtocols.Ssl3, false, 
				//	new AsyncCallback(ProcessDnsInformation), 
				//	new tracessl() { value = 10009 });
				
				//sslStream.EndAuthenticateAsClient(result);
				//var handle = result.AsyncWaitHandle;

				Console.WriteLine($"SslProtocol: {sslStream.SslProtocol}");
			}
			catch (AuthenticationException e)
			{
				Console.WriteLine("Exception: {0}", e.Message);
				if (e.InnerException != null)
				{
					Console.WriteLine("Inner exception: {0}", e.InnerException.Message);
				}
				Console.WriteLine("Authentication failed - closing the connection.");
				client.Close();
				return;
			}
			// Encode a test message into a byte array.
			// Signal the end of the message using the "<EOF>".
			byte[] messsage = Encoding.UTF8.GetBytes("Hello from the client.<EOF>");
			// Send hello message to the server. 
			sslStream.Write(messsage);
			sslStream.Flush();
			Console.WriteLine($"SslProtocol: {sslStream.SslProtocol}");
			// Read message from the server.
			string serverMessage = ReadMessage(sslStream);
			Console.WriteLine($"SslProtocol: {sslStream.SslProtocol}");
			Console.WriteLine("Server says: {0}", serverMessage);
			// Close the client connection.
			client.Close();
			Console.WriteLine("Client closed.");
		}

		static string ReadMessage(SslStream sslStream)
		{
			// Read the  message sent by the server.
			// The end of the message is signaled using the
			// "<EOF>" marker.
			byte[] buffer = new byte[2048];
			StringBuilder messageData = new StringBuilder();
			int bytes = -1;
			do
			{
				bytes = sslStream.Read(buffer, 0, buffer.Length);
				Console.WriteLine($"SslProtocol: {sslStream.SslProtocol}");
				// Use Decoder class to convert from bytes to UTF8
				// in case a character spans two buffers.
				Decoder decoder = Encoding.UTF8.GetDecoder();
				char[] chars = new char[decoder.GetCharCount(buffer, 0, bytes)];
				decoder.GetChars(buffer, 0, bytes, chars, 0);
				messageData.Append(chars);
				// Check for EOF.
				if (messageData.ToString().IndexOf("<EOF>") != -1)
				{
					break;
				}
			} while (bytes != 0);

			return messageData.ToString();
		}
		private static void DisplayUsage()
		{
			Console.WriteLine("To start the client specify:");
			Console.WriteLine("clientSync machineName [serverName]");
			Console.ReadLine();
			Environment.Exit(1);
		}
		public static int Main(string[] args)
		{
			Thread.Sleep(2000);
			ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
			//SslTcpClient.RunClient("80.241.217.92", "Nikolay");
			SslTcpClient.RunClient("127.0.0.1", "Nikolay");
			Console.ReadLine();
			return 0;
		}
	}
}