// See https://aka.ms/new-console-template for more information
using System.Security.Cryptography.X509Certificates;



X509Certificate2Collection collection = new X509Certificate2Collection();
collection.Import(@"C:\Users\Matheus\Downloads\gts1c3.der");
foreach (X509Certificate2 cert in collection)
{
    X509Chain ch = new X509Chain();
    ch.ChainPolicy.RevocationMode = X509RevocationMode.Online; //Verificação online da CRL
    //ch.ChainPolicy.DisableCertificateDownloads = true;
    ch.Build(cert);
    int elementCount = ch.ChainElements.Count;
    Console.WriteLine("=======================================");
    Console.WriteLine("Dados do certificado selecionado");
    Console.WriteLine("=======================================");
    Console.WriteLine("Emissor: {0}", cert.Issuer);
    Console.WriteLine("Requerente: {0}", cert.Subject);
    Console.WriteLine();
    Console.WriteLine();
    Console.WriteLine("=======================================");
    Console.WriteLine("Informações da cadeia de certificados");
    Console.WriteLine("=======================================");
    Console.WriteLine("Chain revocation mode: {0}", ch.ChainPolicy.RevocationMode);
    Console.WriteLine("Chain verification flag: {0}", ch.ChainPolicy.VerificationFlags);
    Console.WriteLine("Chain verification time: {0}", ch.ChainPolicy.VerificationTime);
    Console.WriteLine("Number of chain elements: {0}", ch.ChainElements.Count);
    Console.WriteLine();
    Console.WriteLine();
    Console.WriteLine("=======================================");
    Console.WriteLine("Certificados da cadeia de certificados");
    Console.WriteLine("=======================================");
    foreach (X509ChainElement element in ch.ChainElements)
    {
        Console.WriteLine("Certificado");
        Console.WriteLine("Emissor: {0}", element.Certificate.Issuer);
        Console.WriteLine("Requerente: {0}", element.Certificate.Subject);
        Console.WriteLine("Valido a partir de: {0}", element.Certificate.NotBefore);
        Console.WriteLine("Valido até: {0}", element.Certificate.NotAfter);
        Console.WriteLine("Element information: {0}", element.Information);
        Console.WriteLine("Número de extensões: {0}{1}", element.Certificate.Extensions.Count, Environment.NewLine);
        if(element.Certificate.Extensions.Count > 0)
        {
            foreach(var extensao in element.Certificate.Extensions)
            {
                Console.WriteLine("Oid: {0}", extensao.Oid.Value);
                extensao.RawData.
                Console.WriteLine("Nome: {0}", extensao.Oid.FriendlyName);
            }
        }

        if (ch.ChainStatus.Length > 1)
        {
            for (int index = 0; index < element.ChainElementStatus.Length; index++)
            {
                Console.WriteLine(element.ChainElementStatus[index].Status);
                Console.WriteLine(element.ChainElementStatus[index].StatusInformation);
            }
        }
        Console.WriteLine();
        Console.WriteLine();
    }

}
