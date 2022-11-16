// See https://aka.ms/new-console-template for more information
using System.Security.Cryptography.X509Certificates;

namespace MyApp
{
    internal class Program
    {
        static void Main()
        {
            var extensoes = new List<string> { ".pfx", ".cer", ".crt", ".der" }; // extensões permitidas

            string opcao = "1";
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Extensões permitidas: {0}", string.Join(",", extensoes));
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("1 - Iniciar");
            opcao = Console.ReadLine();
            Console.Write("Insira o diretório em que as autoridades de certificação confiáveis se encontram: ");
            string diretorioCertificados = Console.ReadLine();
            while (!Directory.Exists(diretorioCertificados))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Insira um caminho de diretório existente!");
                Console.ForegroundColor = ConsoleColor.White;
                Console.Write("Insira o diretório em que as autoridades de certificação confiáveis se encontram: ");
                diretorioCertificados = Console.ReadLine();
            }
            string[] arqs = Directory.GetFiles(diretorioCertificados);
            var arquivos = arqs.Where(c => extensoes.Contains(Path.GetExtension(@c))).ToList(); //obter apenas arquivos de certificado

            while (opcao != "2")
            {
                X509Certificate2Collection collection = new X509Certificate2Collection();
                Console.Write("Insira o caminho do certificado a ser validado: ");
                string caminhoArquivo = Console.ReadLine();
                string ext = Path.GetExtension(@caminhoArquivo);

                while (!extensoes.Contains(ext) || string.IsNullOrWhiteSpace(ext))
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Arquivo inválido, insira um arquivo com extensões {0}!", string.Join(",", extensoes));
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.Write("Insira o caminho do certificado a ser validado: ");
                    caminhoArquivo = Console.ReadLine();
                    ext = Path.GetExtension(@caminhoArquivo);
                }

                collection.Import(@caminhoArquivo);
                //Listagem de info
                ListarInformacoesCert(collection);
                //Validar AC
                ValidarCertificado(collection, arquivos);

                Console.WriteLine("Digite 2 para sair ou qualquer tecla para continuar e tecle enter.");
                opcao = Console.ReadLine();
                Console.Clear();
            }
        }

        public static void ValidarCertificado(X509Certificate2Collection collection, List<string> arqs)
        {
            bool certValido = false;
            foreach (string certRaiz in arqs)
            {
                X509Certificate2 certAutoridadeRaiz = new X509Certificate2(@certRaiz);
                string numeroExtensaoRaiz = "";
                foreach (var extensao in certAutoridadeRaiz.Extensions)
                {
                    if (extensao.Oid.FriendlyName == "Subject Key Identifier" || extensao.Oid.FriendlyName == "Identificador da Chave de Requerente")
                    {
                        X509SubjectKeyIdentifierExtension ext = (X509SubjectKeyIdentifierExtension)extensao;
                        numeroExtensaoRaiz = ext.SubjectKeyIdentifier;
                    }
                }

                X509Chain chCa = new X509Chain();
                chCa.ChainPolicy.RevocationMode = X509RevocationMode.Online; //Verificação online da CRL
                chCa.Build(certAutoridadeRaiz);
                if (chCa.ChainElements.Count == 1) // Verificar se é um certificado raiz
                {
                    foreach (X509Certificate2 cert in collection)
                    {
                        X509Chain ch = new X509Chain();
                        ch.ChainPolicy.RevocationMode = X509RevocationMode.Online; //Verificação online da CRL
                        ch.Build(cert);
                        foreach (X509ChainElement element in ch.ChainElements)
                        {
                            
                            foreach (var extensao in element.Certificate.Extensions)
                            {
                                if (extensao.Oid.FriendlyName == "Subject Key Identifier" || extensao.Oid.FriendlyName == "Identificador da Chave de Requerente")
                                {
                                    X509SubjectKeyIdentifierExtension ext = (X509SubjectKeyIdentifierExtension)extensao;
                                    certValido = numeroExtensaoRaiz == ext.SubjectKeyIdentifier;
                                    if (certValido)
                                    {
                                        Console.ForegroundColor = ConsoleColor.Green;
                                        Console.WriteLine("AC Raiz confiável.");
                                        Console.WriteLine("Identificador da Chave de Requerente: {0}", numeroExtensaoRaiz);
                                        Console.WriteLine("Requerente: {0}", element.Certificate.Subject);
                                        Console.WriteLine("Caminho do certificado: {0}", certRaiz);
                                        Console.WriteLine();
                                        Console.ForegroundColor = ConsoleColor.White;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                if (certValido)
                    break;
            }
            if (!certValido)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Não foi identificada nenhuma autoridade de certificação raiz confiável.");
                Console.ForegroundColor = ConsoleColor.White;
            }
        }

        public static void ListarInformacoesCert(X509Certificate2Collection collection)
        {
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
                Console.WriteLine("Número de certificados na cadeia de certificados: {0}", ch.ChainElements.Count);
                Console.WriteLine();
                Console.WriteLine();
                Console.WriteLine("=======================================");
                Console.WriteLine("Certificados da cadeia de certificados");
                Console.WriteLine("=======================================");
                int qtd = ch.ChainElements.Count;
                foreach (X509ChainElement element in ch.ChainElements)
                {
                    Console.WriteLine("Certificado " + qtd);
                    Console.WriteLine("---------------------------------------------------------");
                    Console.WriteLine("Emissor: {0}", element.Certificate.Issuer);
                    Console.WriteLine("Requerente: {0}", element.Certificate.Subject);
                    Console.WriteLine("Valido a partir de: {0}", element.Certificate.NotBefore);
                    Console.WriteLine("Valido até: {0}", element.Certificate.NotAfter);
                    Console.WriteLine("Número de extensões: {0}{1}", element.Certificate.Extensions.Count, Environment.NewLine);
                    //if (element.Certificate.Extensions.Count > 0)
                    //{
                    //    foreach (var extensao in element.Certificate.Extensions) Listar as extensões
                    //    {
                    //        //Console.WriteLine("Oid: {0}:{1}", extensao.Oid.Value, extensao.Oid.FriendlyName);
                    //    }
                    //}

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
                    qtd -= 1;
                }
            }
        }
    }
}
