using System;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.Threading;

namespace SslServer
{

	public sealed class SslTcpServer
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

		public static bool ValidateCertificate(
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

		static X509Certificate2 serverCertificate = null;
		// The certificate parameter specifies the name of the file 
		// containing the machine certificate.
		public static void RunServer(string certificate)
		{
			serverCertificate = new X509Certificate2(certificate, "test");
			// Create a TCP/IP (IPv4) socket and listen for incoming connections.
			var _listenSocket = new Socket(
				AddressFamily.InterNetwork,
				SocketType.Stream,
				ProtocolType.Tcp);

			//var remoteEndpoint = new IPEndPoint(IPAddress.Parse("80.241.217.92"), 4301);
			var remoteEndpoint = new IPEndPoint(IPAddress.Parse("127.0.0.1"), 4301);

			_listenSocket.Bind(remoteEndpoint);

			_listenSocket.Listen(Int32.MaxValue);

			ListenForClients(_listenSocket);

			Console.WriteLine("Waiting for a client to connect...");
		}
		private static void ListenForClients(Socket socket)
		{
			socket.BeginAccept((result) =>
			{
				new Thread(() =>
				{
					ListenForClients(socket);
				}).Start();
				var clientSocket = socket.EndAccept(result);
				Console.WriteLine("{0}: Connected to the client at {1}.", DateTime.Now, clientSocket.RemoteEndPoint);
				ProcessClient(new NetworkStream(clientSocket));
			}, null);
		}

		static void ProcessClient(NetworkStream client)
		{
			// A client has connected. Create the 
			// SslStream using the client's network stream.
			SslStream sslStream = new SslStream(
				client,
				false,
				new RemoteCertificateValidationCallback(ValidateCertificate),
				null,
				EncryptionPolicy.RequireEncryption
				);

			// Authenticate the server but don't require the client to authenticate.
			try
			{
				sslStream.AuthenticateAsServer(serverCertificate,
					true, SslProtocols.Ssl3, true);
				// Display the properties and settings for the authenticated stream.
				DisplaySecurityLevel(sslStream);
				DisplaySecurityServices(sslStream);
				DisplayCertificateInformation(sslStream);
				DisplayStreamProperties(sslStream);

				// Set timeouts for the read and write to 5 seconds.
				sslStream.ReadTimeout = 5000;
				sslStream.WriteTimeout = 5000;
				// Read a message from the client.   
				Console.WriteLine("Waiting for client message...");
				string messageData = ReadMessage(sslStream);
				Console.WriteLine("Received: {0}", messageData);

				// Write a message to the client.
				byte[] message = Encoding.UTF8.GetBytes("Hello from the server.<EOF>");
				Console.WriteLine("Sending hello message.");
				sslStream.Write(message);
			}
			catch (AuthenticationException e)
			{
				Console.WriteLine("Exception: {0}", e.Message);
				if (e.InnerException != null)
				{
					Console.WriteLine("Inner exception: {0}", e.InnerException.Message);
				}
				Console.WriteLine("Authentication failed - closing the connection.");
				sslStream.Close();
				client.Close();
				return;
			}
			finally
			{
				// The client stream will be closed with the sslStream
				// because we specified this behavior when creating
				// the sslStream.
				sslStream.Close();
				client.Close();
			}
		}
		static string ReadMessage(SslStream sslStream)
		{
			// Read the  message sent by the client.
			// The client signals the end of the message using the
			// "<EOF>" marker.
			byte[] buffer = new byte[2048];
			StringBuilder messageData = new StringBuilder();
			int bytes = -1;
			do
			{
				// Read the client's test message.
				bytes = sslStream.Read(buffer, 0, buffer.Length);

				// Use Decoder class to convert from bytes to UTF8
				// in case a character spans two buffers.
				Decoder decoder = Encoding.UTF8.GetDecoder();
				char[] chars = new char[decoder.GetCharCount(buffer, 0, bytes)];
				decoder.GetChars(buffer, 0, bytes, chars, 0);
				messageData.Append(chars);
				// Check for EOF or an empty message.
				if (messageData.ToString().IndexOf("<EOF>") != -1)
				{
					break;
				}
			} while (bytes != 0);

			return messageData.ToString();
		}
		static void DisplaySecurityLevel(SslStream stream)
		{
			Console.WriteLine("Cipher: {0} strength {1}", stream.CipherAlgorithm, stream.CipherStrength);
			Console.WriteLine("Hash: {0} strength {1}", stream.HashAlgorithm, stream.HashStrength);
			Console.WriteLine("Key exchange: {0} strength {1}", stream.KeyExchangeAlgorithm, stream.KeyExchangeStrength);
			Console.WriteLine("Protocol: {0}", stream.SslProtocol);
		}
		static void DisplaySecurityServices(SslStream stream)
		{
			Console.WriteLine("Is authenticated: {0} as server? {1}", stream.IsAuthenticated, stream.IsServer);
			Console.WriteLine("IsSigned: {0}", stream.IsSigned);
			Console.WriteLine("Is Encrypted: {0}", stream.IsEncrypted);
		}
		static void DisplayStreamProperties(SslStream stream)
		{
			Console.WriteLine("Can read: {0}, write {1}", stream.CanRead, stream.CanWrite);
			Console.WriteLine("Can timeout: {0}", stream.CanTimeout);
		}
		static void DisplayCertificateInformation(SslStream stream)
		{
			Console.WriteLine("Certificate revocation list checked: {0}", stream.CheckCertRevocationStatus);

			X509Certificate localCertificate = stream.LocalCertificate;
			if (stream.LocalCertificate != null)
			{
				Console.WriteLine("Local cert was issued to {0} and is valid from {1} until {2}.",
					localCertificate.Subject,
					localCertificate.GetEffectiveDateString(),
					localCertificate.GetExpirationDateString());
			}
			else
			{
				Console.WriteLine("Local certificate is null.");
			}
			// Display the properties of the client's certificate.
			X509Certificate remoteCertificate = stream.RemoteCertificate;
			if (stream.RemoteCertificate != null)
			{
				Console.WriteLine("Remote cert was issued to {0} and is valid from {1} until {2}.",
					remoteCertificate.Subject,
					remoteCertificate.GetEffectiveDateString(),
					remoteCertificate.GetExpirationDateString());
			}
			else
			{
				Console.WriteLine("Remote certificate is null.");
			}
		}
		private static void DisplayUsage()
		{
			Console.WriteLine("To start the server specify:");
			Console.WriteLine("serverSync certificateFile.cer");
			Console.ReadLine();
			Environment.Exit(1);
		}
		public static int Main(string[] args)
		{
			ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
			var basePath = AppDomain.CurrentDomain.BaseDirectory;
			var certificate = basePath + "\\dbserver.pfx";
			SslTcpServer.RunServer(certificate);
			Console.ReadLine();
			return 0;
		}
	}
}
