using System;
using System.Linq;
using DBreeze.Utils;
using NBitcoin;
using NBitcoin.Stealth;

namespace NBitcoinExample
{
    public class Test1
    {

        public static void Main(string[] args)
        {
            test13();
        }

        public static void test_1()
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

            BitcoinAddress addressCopy = BitcoinAddress.Create("15UkDFGJN3bJsnUuDY41pqnfYBCVVG5YS3", Network.Main);

            Console.WriteLine("Public Key Hash: {0}", addressCopy.ScriptPubKey);


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

        public static void test11()
        {

            //P2PK ONLY!!
            /**
2 02a540886615d78d8c4b465563df79c29358b372a86754dad4fb3d5c9b64f146e0 03e835e7578937577a04d367f67d5a7e4fd82c2c24b050507f9e3adb19315e8587 0346d07bad08f024a0738b2af06fceca157c0a22f4404e1fc1a9aca96d7fb235d8 3 OP_CHECKMULTISIG
522102A540886615D78D8C4B465563DF79C29358B372A86754DAD4FB3D5C9B64F146E02103E835E7578937577A04D367F67D5A7E4FD82C2C24B050507F9E3ADB19315E8587210346D07BAD08F024A0738B2AF06FCECA157C0A22F4404E1FC1A9ACA96D7FB235D853AE
OP_HASH160 3abcedad4d2603b3918c763f68d653337118f228 OP_EQUAL
373bSeUy8BWiTtAVat74UWZNiKncoWEczs
{
    "hash": "c2d66bb2039cae5fdddcbc361d6e3bd94de6ac6f7c518369d0147b341db169d4",
    "ver": 1,
    "vin_sz": 1,
    "vout_sz": 1,
    "lock_time": 0,
    "size": 231,
    "in": [
    {
        "prev_out": {
        "hash": "91beb8f4a17ac3973fe91cc749aa972e12808781b61964d7d862f573c29fd87e",
        "n": 0
        },
        "scriptSig": "0 3045022100a617233440e64c7a65e510df83b7323e8d957f84e95df0d2762eb41b349af89a02207f7228ad0e8d24e1e2cabf799f20ad11a8d00159a6d7ad0bbea24daa091ffdc501 3044022039731d93bc637b7a5e7ee6535329d4369544bde08d239b2dc91181ac4cecc45902205d3a4e157a57404fe364e492d3f77471287d222d0c11869559e1a86c12c61b2701"
    }
    ],
    "out": [
    {
        "value": "1.00000000",
        "scriptPubKey": "OP_DUP OP_HASH160 311fce10cc11a8c5d2fe4a6e47606a1c38e2d333 OP_EQUALVERIFY OP_CHECKSIG"
    }
    ]
}
             */

            Key bob = new Key();
            Key alice = new Key();
            Key satoshi = new Key();

            var scriptPubKey = PayToMultiSigTemplate.
                Instance.
                GenerateScriptPubKey(2, new[] { bob.PubKey, alice.PubKey, satoshi.PubKey });

            Console.WriteLine(scriptPubKey);
            Console.WriteLine(scriptPubKey.ToBytes().ToHexFromByteArray());
            Console.WriteLine(scriptPubKey.Hash.ScriptPubKey);

            Console.WriteLine(scriptPubKey.Hash.ScriptPubKey.GetDestinationAddress(Network.Main));


            Transaction received = new Transaction();

            received.Outputs.Add(new TxOut(Money.Coins(1.0m), scriptPubKey));

            Coin coin = received.Outputs.AsCoins().First();


            BitcoinAddress nico = BitcoinAddress.Create("15UkDFGJN3bJsnUuDY41pqnfYBCVVG5YS3", Network.Main);

            TransactionBuilder builder = new TransactionBuilder();

            Transaction unsigned = builder.AddCoins(coin)
                .Send(nico, Money.Coins(1.0m))
                .BuildTransaction(false);
            

            //Alice
            builder = new TransactionBuilder();

            Transaction aliceSigned = builder.AddCoins(coin).
                AddKeys(alice).
                SignTransaction(unsigned);


            builder = new TransactionBuilder();

            Transaction satoshiSigned =
                builder.AddCoins(coin).
                AddKeys(satoshi).
                SignTransaction(unsigned);

            builder = new TransactionBuilder();
            Transaction fullySigned = builder.AddCoins(coin) 
                . CombineSignatures(satoshiSigned, aliceSigned);

            Console.WriteLine(fullySigned);

        }

        public static void test12()
        {

            //P2SH ONLY!!
            /**
2 02e118ab72ed13c00a38f35e35f7a466190f0d75504a24789346da7ddd69d5c017 037f03bcd42380d9b631c1215f6dd2361e5e82935aadd6bb18312d3c7a05bc2660 03ef157bed063b11216b65c292ba2644ec983d773c2b8f92991aaf8a9c59a8c66f 3 OP_CHECKMULTISIG
522102E118AB72ED13C00A38F35E35F7A466190F0D75504A24789346DA7DDD69D5C01721037F03BCD42380D9B631C1215F6DD2361E5E82935AADD6BB18312D3C7A05BC26602103EF157BED063B11216B65C292BA2644EC983D773C2B8F92991AAF8A9C59A8C66F53AE
OP_HASH160 ba2cb82665d12eebf8c86a4094bba3fdb3d3e9c4 OP_EQUAL
3JfRBNtKneXVwaLPtWNLm1jq4bZoJ8U5r8
{
    "hash": "6351fa727d06c422c3d0174c106277a806a9737c61393faf72f8ff9b619df328",
    "ver": 1,
    "vin_sz": 1,
    "vout_sz": 1,
    "lock_time": 0,
    "size": 337,
    "in": [
    {
        "prev_out": {
        "hash": "087271cfb947283cef0642aff65b26afc4740681bfbc92106208da6e0e8159da",
        "n": 0
        },
        "scriptSig": "0 304402207012e0a8834ef1f0745af45d25b18185dcfe8b6e6ed87177212822ab369bf4c102207db03d3f7085e20f507f39ab72908df1999bcf2c80aee7f659441cc42be9133e01 3044022008798229beaf1fec9b7b4ea2256847d98ccb7f7cf0c8f5d2e4f3a9d6780efffc02202df9190d5b7ab44ec8772c3ac9b8c3a6a12b6ce4f537f16e0448c3af1215640e01 522102e118ab72ed13c00a38f35e35f7a466190f0d75504a24789346da7ddd69d5c01721037f03bcd42380d9b631c1215f6dd2361e5e82935aadd6bb18312d3c7a05bc26602103ef157bed063b11216b65c292ba2644ec983d773c2b8f92991aaf8a9c59a8c66f53ae"
    }
    ],
    "out": [
    {
        "value": "1.00000000",
        "scriptPubKey": "OP_DUP OP_HASH160 311fce10cc11a8c5d2fe4a6e47606a1c38e2d333 OP_EQUALVERIFY OP_CHECKSIG"
    }
    ]
}
             */
            Key bob = new Key();
            Key alice = new Key();
            Key satoshi = new Key();

            var redeemScript = PayToMultiSigTemplate.
                Instance.
                GenerateScriptPubKey(2, new[] { bob.PubKey, alice.PubKey, satoshi.PubKey });

            Console.WriteLine(redeemScript);
            Console.WriteLine(redeemScript.ToBytes().ToHexFromByteArray());
            Console.WriteLine(redeemScript.Hash.ScriptPubKey);

            Console.WriteLine(redeemScript.Hash.ScriptPubKey.GetDestinationAddress(Network.Main));


            Transaction received = new Transaction();

            received.Outputs.Add(new TxOut(Money.Coins(1.0m), redeemScript.Hash));

            ScriptCoin coin = received.Outputs.AsCoins().First().ToScriptCoin(redeemScript);


            BitcoinAddress nico = BitcoinAddress.Create("15UkDFGJN3bJsnUuDY41pqnfYBCVVG5YS3", Network.Main);

            TransactionBuilder builder = new TransactionBuilder();

            Transaction unsigned = builder.AddCoins(coin)
                .Send(nico, Money.Coins(1.0m))
                .BuildTransaction(false);


            //Alice
            builder = new TransactionBuilder();

            Transaction aliceSigned = builder.AddCoins(coin).
                AddKeys(alice).
                SignTransaction(unsigned);


            builder = new TransactionBuilder();

            Transaction satoshiSigned =
                builder.AddCoins(coin).
                    AddKeys(satoshi).
                    SignTransaction(unsigned);

            builder = new TransactionBuilder();
            Transaction fullySigned = builder.AddCoins(coin)
                .CombineSignatures(satoshiSigned, aliceSigned);

            Console.WriteLine(fullySigned);

        }

        public static void test13()
        {
            /**
bob:OP_DUP OP_HASH160 778ff3fb70ee72068c9f95e90c9b7cf67ab22b22 OP_EQUALVERIFY OP_CHECKSIG
alice:OP_DUP OP_HASH160 ffd8e43f2693ba52818c8fcbbc60993342e9f60a OP_EQUALVERIFY OP_CHECKSIG
bobAlice:2 03588aa0a680b5411fd9a38e12b252d6862d0aa4deaefe608007797ca3ede228a4 03c1520ec0a475926cde636970f676df0fc9426afb87e085dd3168c01f82d2d52d 2 OP_CHECKMULTISIG
{
  "hash": "a26ee1943cd2a81329b6dc60eb417581617c0a966b11108d5b284d1e5a6a312b",
  "ver": 1,
  "vin_sz": 3,
  "vout_sz": 6,
  "lock_time": 0,
  "size": 706,
  "in": [
    {
      "prev_out": {
        "hash": "d4868dc56115a8abee6cce893441a1b08dd59b77408caf9a1c66c6636ab8b2ae",
        "n": 1
      },
      "scriptSig": "30440220211d317e76aeadb99e319998c6d273726bbaf0e79c10f83eb790210ba06629cf02201997ac37ab00fd6652516be555813201958551702f53ed7b957122dd2e54eede01 03588aa0a680b5411fd9a38e12b252d6862d0aa4deaefe608007797ca3ede228a4"
    },
    {
      "prev_out": {
        "hash": "d4868dc56115a8abee6cce893441a1b08dd59b77408caf9a1c66c6636ab8b2ae",
        "n": 0
      },
      "scriptSig": "30440220517f9edc2518713f928706f072f0a4a70f1f857247278fc7dcbf10756b832b6402205981383f3110c3bfbb7c93f8de821b99142cdc1f33cbbebf3a361f435143be2c01"
    },
    {
      "prev_out": {
        "hash": "d4868dc56115a8abee6cce893441a1b08dd59b77408caf9a1c66c6636ab8b2ae",
        "n": 2
      },
      "scriptSig": "0 3044022003d18f37cf84f14770583fda0d3c20007d21ac59646976ffaf0bc72922df9dec02202ef1570ed671e83da43d88b40e4153f6d2b81748717b8a2134feb9fe50fd2c3301 304402202343c23b2931ddd30018ddc0d4b080feda2c8d89d7f158ccafa0e1bd5ad0e5db022044a4c3f8f58008a1468df7503f3c36192feb0763b17ae1be38dfdf1f1b7beefa01"
    }
  ],
  "out": [
    {
      "value": "0.80000000",
      "scriptPubKey": "OP_DUP OP_HASH160 778ff3fb70ee72068c9f95e90c9b7cf67ab22b22 OP_EQUALVERIFY OP_CHECKSIG"
    },
    {
      "value": "0.20000000",
      "scriptPubKey": "OP_DUP OP_HASH160 52e0e8069de80204d818ecc35d3c4405f82d857b OP_EQUALVERIFY OP_CHECKSIG"
    },
    {
      "value": "0.70000000",
      "scriptPubKey": "OP_DUP OP_HASH160 ffd8e43f2693ba52818c8fcbbc60993342e9f60a OP_EQUALVERIFY OP_CHECKSIG"
    },
    {
      "value": "0.30000000",
      "scriptPubKey": "OP_DUP OP_HASH160 52e0e8069de80204d818ecc35d3c4405f82d857b OP_EQUALVERIFY OP_CHECKSIG"
    },
    {
      "value": "0.49990000",
      "scriptPubKey": "2 03588aa0a680b5411fd9a38e12b252d6862d0aa4deaefe608007797ca3ede228a4 03c1520ec0a475926cde636970f676df0fc9426afb87e085dd3168c01f82d2d52d 2 OP_CHECKMULTISIG"
    },
    {
      "value": "0.50000000",
      "scriptPubKey": "OP_DUP OP_HASH160 52e0e8069de80204d818ecc35d3c4405f82d857b OP_EQUALVERIFY OP_CHECKSIG"
    }
  ]
}             */
            var bob = new Key();
            var alice = new Key();
            var bobAlice = PayToMultiSigTemplate.Instance
                . GenerateScriptPubKey(2, bob.PubKey, alice.PubKey);


            Console.WriteLine($"bob:{bob.ScriptPubKey}");
            Console.WriteLine($"alice:{alice.ScriptPubKey}");
            Console.WriteLine($"bobAlice:{bobAlice}");

      
            Transaction init = new Transaction();

            //Create fake coins
            init.Outputs.Add(new TxOut(Money.Coins(1.0m), alice.PubKey));
            init.Outputs.Add(new TxOut(Money.Coins(1.0m), bob.PubKey.Hash));
            init.Outputs.Add(new TxOut(Money.Coins(1.0m), bobAlice));

            var CArr = init.Outputs.AsCoins().ToArray();
            var aliceCoin =CArr[0];
            var bobCoin = CArr[1];
            var bobAliceCoin = CArr[2];

            var satoshi = new Key();

            var builder = new TransactionBuilder();
            Transaction tx = builder
                .AddCoins(bobCoin)
                .AddKeys(bob)
                .Send(satoshi, Money.Coins(0.2m))
                .SetChange(bob)
                .Then()
                .AddCoins(aliceCoin)
                .AddKeys(alice)
                .Send(satoshi, Money.Coins(0.3m))
                .SetChange(alice)
                .Then()
                .AddCoins(bobAliceCoin)
                .AddKeys(bob, alice)
                .Send(satoshi, Money.Coins(0.5m))
                .SetChange(bobAlice)
                .SendFees(Money.Coins(0.0001m))
                .BuildTransaction(sign: true);

            Console.WriteLine(tx);

        }
    }
}
