using Stratis.Bitcoin.Builder;
using Stratis.Bitcoin.Configuration;
using System;
using System.Linq;
using System.Threading.Tasks;
using DBreeze.Utils;
using NBitcoin;
using Stratis.Bitcoin;
using Stratis.Bitcoin.Features.BlockStore;
using Stratis.Bitcoin.Features.Consensus;
using Stratis.Bitcoin.Features.MemoryPool;
using Stratis.Bitcoin.Features.Miner;
using Stratis.Bitcoin.Features.RPC;
using Stratis.Bitcoin.Utilities;
using Microsoft.Extensions.DependencyInjection;
using NBitcoin.Stealth;

namespace Stratis.BitcoinD
{
    public class Program
    {

        public static void Main(string[] args)
        {
            test1();
        }

        public static void test1()
        {
            Key key = new Key(); //generates a new private key.  
            PubKey pubKey = key.PubKey; //gets the matching public key.

            string hexpub = pubKey.ToHex();

            PubKey pubKeyCopy = new PubKey(hexpub);

            Console.WriteLine("Public Key: {0}", pubKey);

            Console.WriteLine("PublicCopy Key: {0}", pubKeyCopy);


            KeyId hash = pubKey.Hash; //gets a hash of the public key.  
            Console.WriteLine("Hashed public key: {0}", hash);
            BitcoinAddress address = pubKey.GetAddress(Network.Main); //retrieves the  bitcoin address.  

            Console.WriteLine("Pirvate Key: {0}", key.GetBitcoinSecret(Network.Main).ToString());

            Console.WriteLine("Address: {0}", address);
            Script scriptPubKeyFromAddress = address.ScriptPubKey;
            Console.WriteLine("ScriptPubKey from address: {0}", scriptPubKeyFromAddress);
            Script scriptPubKeyFromHash = hash.ScriptPubKey;
            Console.WriteLine("ScriptPubKey from hash: {0}", scriptPubKeyFromHash);
            Console.WriteLine("ScriptPubKey from PK: {0}", pubKey.ScriptPubKey);



        }

        public static void test2()
        {
            Key key = Key.Parse("L1BwppiN4Vh62aUomi3YGKts2Vm1Tr5iDjuCxXop8DNJQmQqsib1");

            var sec = new BitcoinSecret("L1BwppiN4Vh62aUomi3YGKts2Vm1Tr5iDjuCxXop8DNJQmQqsib1");

            PubKey pubKey = key.PubKey; //gets the matching public key.
            Console.WriteLine("Public Key: {0}", pubKey);

            Console.WriteLine("Public Key2: {0}", sec.PubKey);

            BitcoinAddress address = pubKey.GetAddress(Network.Main); //retrieves the  bitcoin address.  
            Console.WriteLine("Address: {0}", address);
        }


        public static void test3()
        {
            Script scriptPubKey = new Script("OP_DUP OP_HASH160 311fce10cc11a8c5d2fe4a6e47606a1c38e2d333 OP_EQUALVERIFY OP_CHECKSIG");

            KeyId hash = (KeyId)scriptPubKey.GetDestination();
            Console.WriteLine("Public Key Hash: {0}", hash);

            BitcoinAddress address = scriptPubKey.GetDestinationAddress(Network.Main);
            Console.WriteLine("Bitcoin Address: {0}", address);
        }

        public static void test4()
        {
            var bitaps = new BitapsTransactionRepository();
            Transaction transaction = bitaps.Get("94b774e1c67e57c161d52ffce3e6e5f92b48d74aea0fa75799dd45f64876163a");
            Console.WriteLine(transaction.ToString());
        }
        public static void test5()
        {
            var tx = Transaction.Parse("01000000010e8305a12266d630534ce2e3d4af138b478b78408e4c3d089c61ec9e0bf67f5d010000006a473044022048c6b932125ae289e9a399b61429aee36fd40dc68e72f38f74e15e97389d182e02203d23c86bd67cfd7dd7f7eaaac2b5b7dc013bb2dad5d9846e8217a738838c93d00121023e0c178d55ff82a14dbf5e5e692291aba4d552a9134deebd91418f5dc8887775feffffff026e740f00000000001976a914304808097d5a9555f0e4215eebb24d727ddda48888ac10090500000000001976a9140b94fc438393564732c7762450b246ede6e3e0e988acd55c0700");

            Console.WriteLine(tx.ToString());

            var result = PayToPubkeyHashTemplate.Instance.ExtractScriptSigParameters(tx.Inputs[0].ScriptSig);


            Script.VerifyScript(result.ScriptPubKey, tx, 0, tx.TotalOut);
        }

        public static void test6()
        {
            /**
             * Master key : xprv9s21ZrQH143K4Fo9LWhEsodgYNAbX6i5sTfow36ZQzH3oE69PtADYbFpB7Xk7bwiLQ3BtW7o6CtvdD93otdrmxaQJBvRiTNrZ9J7qhhgDZX
             * Master Address : 1NYcvwHgZcdjqKWDQqudsdN5C6A6ixrCDa
             * 
             * Key 0 : xprv9vdu2PEU7frHvqCJ9haYvdg7Eiq1CigmeMrN7kPCxUJGua7s8Cwbj6M1DRanJptz1GAjZuV2uhnoGNGkudKZMhKtpYW6LZNgozTjjLyCYyX
             * Key 1 : xprv9vdu2PEU7frHy37wm4ZiR4wLFPht2f23z3wEJh2UDdtYdPGbdit4Nz1k4Q9vYwtqcemgKT2EEnguFkEMTZvurE7ux4Rs3y3FsuVFW2KF6LB
             * Key 2 : xprv9vdu2PEU7frJ23iT6pcEuBRm7vCd4nKzBm9ptXcWhPNKWxi45E6De8wdZHFG5S7AuN9GANQQrq7jsTDmskusMGY4kzfNNPWWMERxmeYBFNf
             * Key 3 : xprv9vdu2PEU7frJ5ExhAJgM334xhm1yRtSPaP17CK5eWg6jSRX3dEexoCkQTs2XAaPBncLBunsG8yjHf9p9MRdz7E192ztqa3DVshrs4SjT76i
             * Key 4 : xprv9vdu2PEU7frJ8WEnAx81LxYZ13c118gJAxi2GwqKoWHdJUWCpLJJo2d5atbrrXpjjQp7Aq6HtWa4qUA31Kwbb3j2BwAbgmqZVzxBq46iBia
             */
            ExtKey masterKey = new ExtKey();
            Console.WriteLine("Master key : " + masterKey.ToString(Network.Main));
            Console.WriteLine("Master Address : " + masterKey.ScriptPubKey.GetDestinationAddress(Network.Main));

            for (int i = 0; i < 5; i++)
            {
                ExtKey key = masterKey.Derive((uint)i);
                Console.WriteLine("Key " + i + " : " + key.ToString(Network.Main));
            }
        }

        public static void test7()
        {
            //BIP32
            var masterKey = ExtKey.Parse("xprv9s21ZrQH143K4Fo9LWhEsodgYNAbX6i5sTfow36ZQzH3oE69PtADYbFpB7Xk7bwiLQ3BtW7o6CtvdD93otdrmxaQJBvRiTNrZ9J7qhhgDZX", Network.Main);

            Console.WriteLine("Master Address : " + masterKey.ScriptPubKey.GetDestinationAddress(Network.Main));

            int i = 0;
            ExtKey key = masterKey.Derive((uint)i);
            Console.WriteLine("Key " + i + " : " + key.ToString(Network.Main));

            //BIP38
            var masterPubKey = masterKey.Neuter();

            string strMasterPubKey = masterPubKey.ToString(Network.Main);
            Console.WriteLine("masterPubKey : " + strMasterPubKey);


            ///The payment server get strMasterPubKey to generate pubkey index=1  
            ExtPubKey pubkey1 = masterPubKey.Derive((uint)1);

            //You get the private key of pubkey index=1  
            ExtKey key1 = masterKey.Derive((uint)1);

            //Check it is legit  
            Console.WriteLine("Generated address : " + pubkey1.PubKey.GetAddress(Network.Main));
            Console.WriteLine("Expected address : " + key1.PrivateKey.PubKey.GetAddress(Network.Main));


        }


        public static void test8()
        {

            /**
             *Raw Mnemonic words:suspect picture bamboo sail grant fury search wink daughter achieve noodle talk
             *
             * Key:xprv9s21ZrQH143K2GWr3PQZ66oGqtdztXZLr55Ss64bRvUri6RcMyHSSswpbauPqetrS6Q9UgThvwanUGr96xFZK8BN8a3u9qqkvcEZk9BEFEp
             * 
             * Key:xprv9s21ZrQH143K49oDTrX7RYiXYRzb38y5VEM7TXNXEhFkfwUerXHxjTt1Au23tHe1E7Du91GEhk9EDs3ihX8fnY7L1nuJaznh4wh7n3oy76w
             * 
             */

            Mnemonic mnemo = new Mnemonic(Wordlist.English, WordCount.Twelve);
            Console.WriteLine("Raw Mnemonic words:" + mnemo);

            ExtKey hdRoot = mnemo.DeriveExtKey("my pwd");
            Console.WriteLine("Key:" + hdRoot.ToString(Network.Main));

            Console.WriteLine();

            ExtKey hdRoot2 = mnemo.DeriveExtKey("f517f42e808d92f86b4bf8f303db5616");

            Console.WriteLine("Key:" + hdRoot2.ToString(Network.Main));


        }


        public static void test9()
        {
            //BIP39
            Mnemonic mnemo = new Mnemonic("suspect picture bamboo sail grant fury search wink daughter achieve noodle talk");

            ExtKey hdRoot = mnemo.DeriveExtKey("my pwd");
            Console.WriteLine("Key:" + hdRoot.ToString(Network.Main));

            Console.WriteLine();

            ExtKey hdRoot2 = mnemo.DeriveExtKey("f517f42e808d92f86b4bf8f303db5616");

            Console.WriteLine("Key:" + hdRoot2.ToString(Network.Main));
        }


        public static void test10()
        {
            var AliceScanKey = new Key();
            var AliceSpendKey = new Key();

            Console.WriteLine("AliceScanKey:" + AliceScanKey.ToString(Network.Main));
            Console.WriteLine($"AliceScanKey ScriptPubKey:{AliceScanKey.PubKey}[{AliceScanKey.ScriptPubKey}]");

            Console.WriteLine("AliceSpendKey:" + AliceSpendKey.ToString(Network.Main));
            Console.WriteLine($"AliceSpendKey ScriptPubKey:{AliceSpendKey.PubKey}[{AliceSpendKey.ScriptPubKey}]");


            var stealthAddress = new BitcoinStealthAddress(
                scanKey: AliceScanKey.PubKey,
                pubKeys: new[] { AliceSpendKey.PubKey },
                signatureCount: 1,
                bitfield: null,
                network: Network.Main);


            string strStealthAddress = stealthAddress.ToString();
            Console.WriteLine("stealthAddress:" + stealthAddress);

            var stealthAddressBobCopy = new BitcoinStealthAddress(strStealthAddress, Network.Main);

            Console.WriteLine("AliceScanKey[From Bob] ScriptPubKey:" + stealthAddressBobCopy.ScanPubKey);
            Console.WriteLine("AliceSpendKey[From Bob] ScriptPubKey:" + stealthAddressBobCopy.SpendPubKeys[0]);


            var ephemKey = new Key();


            Console.WriteLine("ephemKey:" + ephemKey.ToString(Network.Main));
            Console.WriteLine("ephemKey ScriptPubKey:" + ephemKey.ScriptPubKey);

            Transaction transaction = new Transaction();

            stealthAddressBobCopy.SendTo(transaction, Money.Coins(1.0m), ephemKey);
            Console.WriteLine(transaction);


        }

    }
}
