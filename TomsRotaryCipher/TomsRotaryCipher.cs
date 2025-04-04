using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.CodeDom.Compiler;
using System.Security.Policy;
using System.IO;
using static StoneAgeEncryptionService.TomsRotaryCipher;
using System.Net;

namespace StoneAgeEncryptionService
{
    //Trademark Notices/Disclaimer:

    //TomsRotaryCipher is a c# encryption/decryption DLL that belongs to namespace StoneAgeEncryptionService.
    //The source code is offered in GitHub under the MIT license. There are no guarantees the compiled DLL will
    //perform per specification or to anyone's expectations. 

    //Sigaba (Trademarked) was the original rotor skipping hardware of the 1950s comprising of index and control
    //rotors that facilitated a pseudo random skipping pattern of the primary cipher rotors. This idea serves as
    //inspiration for HopScotch, which is done in software, and may not be an accurate representation of the
    //original hardware implementation. There is no association, professional or otherwise, between Sigaba and HopScotch.

    //The German Enigma (Trademarked), was a commercially made encryption machine invented by German engineer
    //Arthur Scherbius in the late-1910s. This machine serves as inspiration for TomsRotaryCipher, which is done in software,
    //and may not be an accurate representation of the original hardware implementation. There is no association,
    //professional or otherwise, between Enigma and TomsRotaryCipher.


    public enum RotaryCipherMode { WithReflector, NoReflector }
    public enum NoReflectorMode { None, Encipher, Decipher}
    public enum NotchPlan { Sequential, HopScotch}
    public enum CBCMode { None, Forward, Reverse }
    public enum DebugMode { No , Yes}

    public class TomsRotaryCipher
    {
        public class Seeds
        {
            public byte[] SeedXOR { get; set; }
            public byte[] SeedIndividualRotors { get; set; }
            public byte[] SeedNotchPlan { get; set; }
            public byte[] SeedTurnOverPositions { get; set; }
            public byte[] SeedStartPositions { get; set; }
        }

        public class Settings
        {
            public string ReflectorDesc;
            public string BranchName = "Enter (Branch) Name for Compile, if multiple DLL versions";
            public int MovingCipherRotors { get; set; }
            public NotchPlan NotchPlan { get; set; }
            public RotaryCipherMode RotaryCipherMode { get; set; }
            public NoReflectorMode NoReflectorMode { get; set; }
            public CBCMode CBCMode { get; set; }
            public DebugMode DebugMode { get; set; }
        }

        public void SetMovingCipherRotors(int Rotors)
        {
            oSettings.MovingCipherRotors = Rotors;
            PopulateIndividualRotorSeeds();
        }

        protected static long HighestIteration;// for analysis
        protected static bool StandardConfig= true; 
        protected int TotalRotors { get { return 2 + oSettings.MovingCipherRotors; } set { } }  // MovingCipherRotors + 2; // need plugboard and reflector

        public Seeds oSeeds = new Seeds();
        public Settings oSettings = new Settings();
        private enum RotorSide : int {Predestined = 0, Calculated = 1}// these values will match the CSV Rotor headings:
                                                                      // Predestined and Calculated for ref. in array
        public byte[] SAES(NotchPlan np, byte[] UserStr,
            RotaryCipherMode em,
            NoReflectorMode nrm,
            CBCMode cm = CBCMode.None,
            DebugMode dm = DebugMode.No
            )
        {
            const int sides = 2;
            const int radix = 256;
            const int randomMultiplier = 32;

            if (oSeeds.SeedNotchPlan is null)
            {
                throw new Exception("Please PopulateSeeds or LoadAll!");
            }

            if (em.Equals(RotaryCipherMode.NoReflector)&& nrm.Equals(NoReflectorMode.None))
            {
                throw new Exception("If RotaryCipherMode = NoReflector, NoReflectorMode cannot be None. Select Encipher or Decipher!");
            }

            if (em.Equals(RotaryCipherMode.WithReflector) && !cm.Equals(CBCMode.None))
            {
                throw new Exception("If RotaryCipherMode = WithReflector, CBCMode must be None.");
            }


            oSettings.CBCMode = cm;
            oSettings.NotchPlan = np;
            int movingCipherRotors = oSettings.MovingCipherRotors;

            byte[] eStartPositions = new byte[TotalRotors - 2];
            AssignStartPositions(ref eStartPositions, BitConverter.ToInt32(oSeeds.SeedStartPositions, 0));

            byte[,,] e = CreateMachine(TotalRotors, sides, radix);
            PopulateRotors(ref e, radix, randomMultiplier, TotalRotors, eStartPositions);

            // make a local copy for speed optimization
            byte[] eSpinFactor = new byte[TotalRotors - 2];

            AssignTurnOverPositions(ref eSpinFactor, BitConverter.ToInt32(oSeeds.SeedTurnOverPositions, 0));

            RotorSpinPln.RotorSpinPlan oSig = new RotorSpinPln.RotorSpinPlan();

            oSettings.MovingCipherRotors = movingCipherRotors;
            oSettings.RotaryCipherMode = em;
            oSettings.NoReflectorMode = nrm;

            // make a local copy of property for speed optimization
            byte[] eVirtualRotorMove = new byte[movingCipherRotors];

            if (StandardConfig)
            {
                // this is the 'standard' configuration
                // Plugboard is at pos 0, Reflector is in the last pos.
                CreatePlugBoard(0, ref e, radix);
                ConfigureRevLookUps(radix, TotalRotors, ref e);
                CreateReflector(TotalRotors - 1, ref e, radix);
            }
            else
            {   // this is where you can be creative, start experimenting..

                // The PlugBoard, Reflector, and Cipher rotors can be created for any rotor in the system.
                // If you change things around, the lookup routines might need changing based on whether Predestined or
                // Calculated are referenced at runtime.

                // Hint: the logic to create PlugBoard and Reflector are different, but seem to be interchangable.

                // here are all available options:

                //CreatePlugBoard(i, ref e, radix);
                //ConfigureMovingCipherRotor(i, ref e, radix);
                //Original_CreateReflector(i, ref e, radix);
                //CreateReflector(i, ref e, radix);

                //create PlugBoard, rotor = 0,
                //CreatePlugBoard(0, ref e, radix);
                Original_CreatePlugBoard(0, ref e, radix);
                //Original_CreateReflector(0, ref e, radix);
                //CreateReflector(0, ref e, radix);

                for (int i = 1; i <= (TotalRotors - 2); i++)
                {
                    ConfigureMovingCipherRotor(i, ref e, radix);
                }

                // create Reflector, rotor = TotalRotors - 1,
                //CreatePlugBoard(TotalRotors - 1, ref e, radix); // plugboard seems to work as Reflector
                //CreateReflector(TotalRotors - 1, ref e, radix);
                Original_CreateReflector(TotalRotors - 1, ref e, radix);
            }

            if (dm.Equals(DebugMode.Yes))
            {
                File.WriteAllText("PlugBoard.csv", ExtractRotorIntoCSV(e, radix, 0));
                for (int rotor = 1; rotor < TotalRotors - 1; rotor++)
                {
                    File.WriteAllText("Rotor" + rotor + ".csv", ExtractRotorIntoCSV(e, radix, rotor));
                }
                File.WriteAllText("Reflector.csv", ExtractRotorIntoCSV(e, radix, TotalRotors - 1));
                // now validate the reflector in case any code changes were made,
                if (!ValidateReflector(e, radix, TotalRotors - 1))
                { // first get Guid to preserve results
                    DateTime dt = DateTime.Now;
                    string post = "TestFailure_" + dt.Year.ToString() + "_" + dt.Month.ToString().PadLeft(2, '0') + "_" + dt.Day.ToString().PadLeft(2, '0') + "_" + Guid.NewGuid().ToString("N").Substring(0, 4);
                    string MainReport= "Results_" + post + ".txt";
                    string ReflectorUniqueName = "Reflector" + post + ".csv";
                    File.WriteAllText(ReflectorUniqueName, ExtractRotorIntoCSV(e, radix, TotalRotors - 1));
                    byte[] ReflectorSeed = new byte[4];
                    PopulateNewSeedForRotors(ref ReflectorSeed, oSeeds.SeedIndividualRotors, oSeeds.SeedIndividualRotors.Length - 4);
                    File.WriteAllText(MainReport, oSettings.ReflectorDesc + Environment.NewLine + "Reflector Failure, Seed =" + BitConverter.ToInt32(ReflectorSeed, 0));
                };
            }

            byte[] Rtn = new byte[UserStr.Length];
            byte currentByte = new byte();
            byte TransformLast = new byte();
            for (int i = 0; i <= UserStr.Length - 1; i++)
            {
                currentByte = UserStr[i];

                byte Transform = currentByte;

                if (cm.Equals(CBCMode.Forward))
                {
                    if (i.Equals(0))
                    {
                        TransformLast = oSeeds.SeedXOR[0]; // IV
                    }
                    Transform = XOR(Transform, TransformLast);
                }

                if (em.Equals(RotaryCipherMode.WithReflector))
                {
                    // take it through PlugBoard, all rotors, and  reflector
                    for (int r = 0; r <= TotalRotors - 1; r++)
                    {
                        Transform = ByteLookupForward(Transform, r, radix, TotalRotors, e, eVirtualRotorMove);
                    }

                    // now backwards through rotors and plugboard 
                    for (int r = TotalRotors - 2; r >= 0; r--)
                    {
                        Transform = ByteLookupReverse(Transform, r, e, eVirtualRotorMove);
                    }
                }
                else
                {
                    if (nrm.Equals(NoReflectorMode.Encipher))
                    {
                        // take it through PlugBoard, all rotors
                        for (int r = 0; r <= TotalRotors - 2; r++)
                        {
                            Transform = ByteLookupForward(Transform, r, radix, TotalRotors, e, eVirtualRotorMove);
                        }
                    }
                    if (nrm.Equals(NoReflectorMode.Decipher))
                    {
                        // now backwards through rotors and plugboard 
                        for (int r = TotalRotors - 2; r >= 0; r--)
                        {
                            Transform = ByteLookupReverse(Transform, r, e, eVirtualRotorMove);
                        }
                    }
                }

                if (cm.Equals(CBCMode.Reverse))
                {
                    if (i.Equals(0))
                    {
                        TransformLast = oSeeds.SeedXOR[0];// IV
                    }
                    else
                    {
                        TransformLast = UserStr[i - 1];
                    }
                    Transform = XOR(Transform, TransformLast);
                }

                Rtn[i] = Transform;
                TransformLast = Transform;

                byte[] bRtn;
                bRtn = oSig.GetNotchPlan(np, movingCipherRotors, i, BitConverter.ToInt32(oSeeds.SeedNotchPlan, 0),
                ref eSpinFactor, radix);

                // spin rotors based on notch plan
                for (int r = 1; r <= TotalRotors - 2; r++)
                {
                    if (bRtn[r - 1].Equals(1))
                    {
                        MoveArrayPointerMainRotors(r, 1, radix, ref eVirtualRotorMove);
                    }
                }
            }
            return Rtn;
        }
        private byte ByteLookupReverse(byte Input, int Rotor, byte[,,] e, byte[] eVirtualRotorMove)
        {
            if ((Rotor.Equals(0))) // stationary rotor, PlugBoard
            {
                return e[Rotor, (int)RotorSide.Calculated , Input];
            }

            int OffsetTst = e[Rotor, (int)RotorSide.Predestined, Input] - eVirtualRotorMove[Rotor - 1];
            return (byte)OffsetTst;
        }
        private byte ByteLookupForward(byte Input, int Rotor, int Radix, int TotalRotors, byte[,,] e, byte[] eVirtualRotorMove)
        {
            if (Rotor.Equals(0)) // stationary rotor PlugBoard
            {
                return e[Rotor, (int)RotorSide.Calculated, Input];
            }
            if ((Rotor.Equals(TotalRotors - 1))) // stationary rotor Reflector
            {
                return e[Rotor, (int)RotorSide.Calculated, Input];
            }

            int Offset = eVirtualRotorMove[Rotor - 1] + Input;
            if (Offset >= Radix)
            {
                Offset = Offset - Radix;
            }

            return e[Rotor, (int)RotorSide.Calculated, Offset];
        }

        private bool ValidateReflector(byte[,,] e, int Radix, int Rotor)
        {// this is to test logic changes, which should be infrequent
         //return true; //bypass
            bool result = true;
            for (int Input = 0; Input < Radix; Input++)
            {
                // check for a match
                if (Input.Equals(e[Rotor, (int)RotorSide.Calculated, Input]))// for the newer Reflector, only the Calculated side can be used
                {result = false;}
            }
            return result;
        }
        private void ConfigureRevLookUps(int Radix, int Rotors, ref byte[,,] e)
        {// populate Main Rotors side 1 (ciphertext) with inverse of side 0 (plaintext) for quick reverse lookups
            for (int iRotor = 1; iRotor <= Rotors - 2; iRotor++)
            {
                ConfigureMovingCipherRotor(iRotor, ref e, Radix);
            }
        }
        private void ConfigureMovingCipherRotor(int Rotor, ref byte[,,] e, int Radix)
        {
            for (int Input = 0; Input <= (Radix - 1); Input++)
            {
                e[Rotor, (int)RotorSide.Calculated, e[Rotor, (int)RotorSide.Predestined, Input]] = (byte)Input;
            }
        }


        private void MoveArrayPointerMainRotors(int Row, int eStartPosition, int Radix, ref byte[] eVirtualRotorMove)
        {
            int iNew = eVirtualRotorMove[Row - 1] + eStartPosition;
            if (iNew.Equals(Radix))
            {
                iNew = 0;
            }
            eVirtualRotorMove[Row - 1] = (byte)iNew;
        }

        private void AssignStartPositions(ref byte[] eStartPositions, int iSeed)
        {
            Random oRandom = new Random(iSeed);
            oRandom.NextBytes(eStartPositions);
        }
        private void AssignTurnOverPositions(ref byte[] eSpinFactor, int iSeed)
        {
            Random oRandom = new Random(iSeed);
            oRandom.NextBytes(eSpinFactor);
            eSpinFactor[0] = 0;
        }
        private string ExtractRotorIntoCSV(byte[,,] b, int radix, int rotor)
        {
            string Out = "Input,Predestined,Calculated" + Environment.NewLine;
            for (int i = 0; i < radix; i++)
            {
                Out += i + "," + b[rotor, 0, i] + "," + b[rotor, 1, i] + Environment.NewLine;
            }
            return Out;
        }

        private void Original_CreatePlugBoard(int rotor, ref byte[,,] b, int radix)
        { // re-create this rotor with seed for more variance:
            byte[,,] bHolding = CreateMachine(1, 2, radix);

            for (int Input = 0; Input <= (radix - 1); Input++)
            {
                bHolding[0, 0, Input] = b[rotor, (int)RotorSide.Predestined, Input];
                bHolding[0, 1, Input] = b[rotor, (int)RotorSide.Calculated, Input];
            }

            /* PlugBoard : igousbtrcpnmefwhqlkavzdyxj
             * PlugBoard : giuobsrtpcmnfehwlqakzvydjx*/
            for (int Input = 0; Input <= (radix - 2); Input += 2)
            {
                bHolding[0, 1, Input] = bHolding[0, 0, Input + 1];
                bHolding[0, 1, Input + 1] = bHolding[0, 0, Input];
            }

            // now update b
            for (int Input = 0; Input <= (radix - 1); Input++)
            {
                b[0, 0, bHolding[0, 0, Input]] = bHolding[0, 1, Input];
                b[0, 1, bHolding[0, 1, Input]] = bHolding[0, 0, Input];
            }
        }

        private void CreatePlugBoard(int rotor, ref byte[,,] b, int radix)
        {// this is new plugboard, works with input and Calculated (side 1),
         // Predestined is used to create Calculated, but is not referenced in code
         //
         // input	Predestined	Calculated
         // 0       122         20
         // 20      111         0

            byte[,,] bHolding = CreateMachine(1, 1, radix);
            /* PlugBoard : igousbtrcpnmefwhqlkavzdyxj
             * PlugBoard : giuobsrtpcmnfehwlqakzvydjx*/
            for (int Input = 0; Input <= (radix - 2); Input += 2)
            {
                bHolding[0, (int)RotorSide.Predestined, Input] = 
                   b[rotor, (int)RotorSide.Predestined, Input + 1];
                bHolding[0, (int)RotorSide.Predestined, Input + 1] = 
                   b[rotor, (int)RotorSide.Predestined, Input];
            }
            // now update b
            for (int Input = 0; Input <= (radix - 1); Input++)
            { 
                b[rotor, (int)RotorSide.Calculated, b[rotor, (int)RotorSide.Predestined, Input]] = 
             bHolding[0, (int)RotorSide.Predestined, Input];
            }
        }
        private void CreateReflector(int rotor, ref byte[,,] b, int radix)
        {// this is the new Reflector:
         // 1. Take opposing inputs (0 and 255)
         // 2. Take Predestined at input 255 (223)
         //    and assign to Calculated at input 125,
         //    which is Predestined at Predestined 0
         // 3. Resume inwards with input (1 and 254), etc. etc.
         //
         // input	Predestined	Calculated
         //  0	        125	        135
         //  125	    224	        223
         //  255	    223	        116

         // input	Predestined	Calculated
         //  1          102         138
         //  102        151         222
         //  254        222         155

            oSettings.ReflectorDesc = "this is the new Reflector, Predestined != Calculated";
            /*Reflector : phafjdsilcebguwyvkotqzmxrn
              Reflector : nrxmzqtokvywugbeclisdjfahp*/
            for (int Input = 0; Input <= (radix - 1); Input++)
            {
                b[rotor, (int)RotorSide.Calculated, 
                b[rotor, (int)RotorSide.Predestined, Input]] = 
                b[rotor, (int)RotorSide.Predestined, radix - Input - 1];
            }
        }
        // this is the Original Reflector, PlainTxt = CipherTxt
        private void Original_CreateReflector(int rotor, ref byte[,,] b, int radix)
        {
            oSettings.ReflectorDesc = "this is the Original Reflector, Predestined = Calculated";
            byte[,,] bHolding = CreateMachine(1, 2, radix);

            for (int Input = 0; Input <= (radix - 1); Input++)
            {
             bHolding[0, (int)RotorSide.Predestined, radix - Input - 1] = 
                b[rotor, (int)RotorSide.Predestined, Input];
             bHolding[0, (int)RotorSide.Calculated, radix - Input - 1] = 
                b[rotor, (int)RotorSide.Calculated, Input]; 
            }

            /*     
            Reflector : phafjdsilcebguwyvkotqzmxrn
            Reflector : nrxmzqtokvywugbeclisdjfahp*/
            int Query = radix - 1;
            for (int Input = 0; Input <= (radix - 1); Input++)
            {
                bHolding[0, (int)RotorSide.Calculated, (radix - Input - 1)] = 
                bHolding[0, (int)RotorSide.Predestined, Input];
            }

            // now update b
            for (int Input = 0; Input <= (radix - 1); Input++)
            {
                b[rotor, (int)RotorSide.Predestined, bHolding[0, 0, Input]] = 
             bHolding[0, (int)RotorSide.Calculated, Input];

                b[rotor, (int)RotorSide.Calculated, 
             bHolding[0, (int)RotorSide.Calculated, Input]] = 
             bHolding[0, (int)RotorSide.Predestined, Input];
            }
        }

        private byte[,,] CreateMachine(int numRotors, int Sides, int Radix)
        {
            byte[,,] e = new byte[numRotors, Sides, Radix];
            return e;
        }

        private void PopulateNewSeedForRotors(ref byte[] newSeed, byte[] SeedRotors, int Start)
        {
            newSeed[0] = SeedRotors[Start];
            Start++;
            newSeed[1] = SeedRotors[Start];
            Start++;
            newSeed[2] = SeedRotors[Start];
            Start++;
            newSeed[3] = SeedRotors[Start];

        }
        private void PopulateRotors(ref byte[,,] b, int Radix, int RandomMultiplier, int Rotors, byte[] eStartPositions)
        { // for Main Rotor Creation
            byte[] newSeed = new byte[4];
            byte[] bOut = new byte[Radix];
            int RotorSeedArrayStart = -4; // inc by 4 to traverse the Rotor Seed Array

            long RandomArraySize = Radix * RandomMultiplier;
            byte[] bNext = new byte[RandomArraySize]; // Need unique numbers only, this is the available pool, larger than required
            for (int rotor = 0; rotor <= Rotors - 1; rotor++)
            {
                // we need to re-seed each rotor with stored 4 byte number
                RotorSeedArrayStart += 4;
                PopulateNewSeedForRotors(ref newSeed, oSeeds.SeedIndividualRotors, RotorSeedArrayStart);
                System.Random oRandom = new System.Random(BitConverter.ToInt32(newSeed, 0));
                oRandom.NextBytes(bNext);
                byte[] bUnique = bNext.Distinct().ToArray();
                if (bUnique.Length.Equals(Radix))
                {// This was eliminated: ConfigureStartPositions(eStartPositions, radix, TotalRotors, ref e);
                 // Run an optimized version of this now: 
                    if (rotor>0&&rotor<(Rotors - 1))
                    {
                        byte Offset = eStartPositions[rotor - 1];
                        Array.Copy(bUnique, Offset, bOut, 0, Radix - Offset);
                        Array.Copy(bUnique, 0, bOut, Radix - Offset, Offset);
                        Array.Copy(bOut, bUnique, Radix);
                    }
                    for (int Input = 0; Input <= Radix - 1; Input++)
                    {
                        b[rotor, (int)RotorSide.Predestined, Input] = bUnique[Input];
                    }
                } else
                {
                    throw new Exception("Rotor does not contain " + Radix.ToString() + " distinct numbers!");
                }
            }
            bOut = null;
        }

        public void PopulateSeeds(
            byte[] bSeedXOR,
            byte[] bSeedNotchPlan,
            byte[] bSeedTurnOverPositions,
            byte[] bSeedStartPositions
)
        {
            // these are used for regression testing
            oSeeds.SeedXOR = bSeedXOR;
            oSeeds.SeedNotchPlan = bSeedNotchPlan;
            oSeeds.SeedStartPositions = bSeedStartPositions;
            oSeeds.SeedTurnOverPositions = bSeedTurnOverPositions;
        }

        public byte[] GetAll()
        {
            return GetSeeds().Concat(GetSettings()).ToArray();
        }

        private byte[] GetSeeds()
        {
            return oSeeds.SeedXOR.Concat(oSeeds.SeedNotchPlan).Concat(oSeeds.SeedStartPositions).Concat(oSeeds.SeedTurnOverPositions).ToArray();
        }

        private byte[] GetSettings()
        {
            byte[] bRotors = BitConverter.GetBytes(oSettings.MovingCipherRotors);
            byte[] bNotchPlan = BitConverter.GetBytes(Convert.ToInt16(oSettings.NotchPlan));
            byte[] bRotaryCipherMode= BitConverter.GetBytes(Convert.ToInt16(oSettings.RotaryCipherMode));
            byte[] bNoReflectorMode = BitConverter.GetBytes(Convert.ToInt16(oSettings.NoReflectorMode));
            byte[] bCBCMode = BitConverter.GetBytes(Convert.ToInt16(oSettings.CBCMode));
            byte[] bRotorsHS = oSeeds.SeedIndividualRotors;
            return bRotors.Concat(bNotchPlan).Concat(bRotaryCipherMode).Concat(bNoReflectorMode).Concat(bCBCMode).Concat(bRotorsHS).ToArray();
        }

        public void LoadAll(byte[] b)
        {
            int i = 0;

            byte[] newArray = b.Skip(i).Take(4).ToArray();
            oSeeds.SeedXOR = newArray;
            i += 4;

            newArray = b.Skip(i).Take(4).ToArray();
            oSeeds.SeedNotchPlan = newArray;
            i += 4;

            newArray = b.Skip(i).Take(4).ToArray();
            oSeeds.SeedStartPositions = newArray;
            i += 4;

            newArray = b.Skip(i).Take(4).ToArray();
            oSeeds.SeedTurnOverPositions = newArray;
            i += 4;

            newArray = b.Skip(i).Take(4).ToArray();
            oSettings.MovingCipherRotors = BitConverter.ToInt32(newArray, 0);
            i += 4;

            newArray = b.Skip(i).Take(2).ToArray();
            oSettings.NotchPlan = (NotchPlan)BitConverter.ToInt16(newArray, 0);
            i += 2;

            newArray = b.Skip(i).Take(2).ToArray();
            oSettings.RotaryCipherMode = (RotaryCipherMode)BitConverter.ToInt16(newArray, 0);
            i += 2;

            newArray = b.Skip(i).Take(2).ToArray();
            oSettings.NoReflectorMode = (NoReflectorMode)BitConverter.ToInt16(newArray, 0);
            i += 2;

            newArray = b.Skip(i).Take(2).ToArray();
            oSettings.CBCMode = (CBCMode)BitConverter.ToInt16(newArray, 0);
            i += 2;

            int RotorSeedsHS = b.Length - i;
            newArray = b.Skip(i).Take(RotorSeedsHS).ToArray();
            oSeeds.SeedIndividualRotors = newArray;
        }

        public void PopulateIndividualRotorSeeds()
        {   // this routine is to a obtain a 4-byte seed for each rotor
            // we could just use oRNG.GetBytes, but I'd rather take it
            // a step further and introduce more logic to faciliate
            // a unique combination of numbers.
            RNGCryptoServiceProvider oRNG1 = new RNGCryptoServiceProvider();
            RNGCryptoServiceProvider oRNG2 = new RNGCryptoServiceProvider();
            {
                int TotalRotors = (oSettings.MovingCipherRotors + 2) * 4;
                oSeeds.SeedIndividualRotors = new byte[TotalRotors];

                byte[] bR1 = new byte[TotalRotors];
                byte[] bR2 = new byte[TotalRotors];

                oRNG1.GetBytes(bR1);
                QuantumShuffle(ref bR1);// bR needs to be scrambled to ensure values are more unique than off-the-shelf

                oRNG2.GetBytes(bR2);
                QuantumShuffle(ref bR2);// bR needs to be scrambled to ensure values are more unique than off-the-shelf

                oSeeds.SeedIndividualRotors = XOR(bR1, bR2);// the final "shuffle" will be an XOR

                oRNG1.Dispose();
                oRNG2.Dispose();

            }
        }

        private void QuantumShuffle(ref byte[] b)
        {// There is a 50% chance of exchanging data between the top and bottom halves of b[]

            // my notes:
            // 1) there are some programming oddities involving r.Next() and min/max values, see the code.

            // 2) Random() is either time dependant (default), OR can accept an
            // integer seed value between 0 to 2_147_483_647.
            // Negative values will be converted to positive, relevant when using 
            // RNGCryptoServiceProvider.GetBytes()

            // it turns out forcing a seed is less likely to result in a collision
            // than using default time, which is more prone to collisions.
            // This is based on my quick testing. Neither are a good options,
            // they are either buggy (time),or limited (since when is Int32 "secure"?)

            // In order to enforce a unique number, a seed could be a hash of time,
            // hardware signature, and process ID (different instances of the same
            // running program should have different process IDs), but those are only
            // my preliminary ideas.
            //
            // "True Randomness" is another rabbit hole to explore

            RNGCryptoServiceProvider oRNGStartSwap = new RNGCryptoServiceProvider();
            RNGCryptoServiceProvider oRNGEndSwap = new RNGCryptoServiceProvider();
            RNGCryptoServiceProvider oRNGDice = new RNGCryptoServiceProvider();
            RNGCryptoServiceProvider oRNGChance = new RNGCryptoServiceProvider();

            Int32 iStartSwap = BitConverter.ToInt32(GetNxt(oRNGStartSwap), 0);
            Int32 iEndSwap = BitConverter.ToInt32(GetNxt(oRNGEndSwap), 0);
            Int32 iDice = BitConverter.ToInt32(GetNxt(oRNGDice), 0);
            Int32 iChance = BitConverter.ToInt32(GetNxt(oRNGChance), 0);

            Random rStartSwap = new Random(iStartSwap);
            Random rEndSwap = new Random(iEndSwap);
            Random rDice = new Random(iDice);
            Random rChance = new Random(iChance);

            int start = 0;
            int mid = b.Length / 2;
            int end = b.Length;
            int StartToSwap;
            int EndToSwap;
            int Chance = 1;
            int bStart;
            int bEnd;
            for (int i = 0; i < end; i++) // 100% of all data can be exchanged.
            {
                //Programming note, r.Next does not behave the way you think it should,
                //add +1 to max value for a possible rtn if it is not a 0-based array

                //get a random location between start and mid
                StartToSwap = rStartSwap.Next(start, mid);
                // get a random location between mid and end
                EndToSwap = rEndSwap.Next(mid, end);
                // roll the dice up to 3 X to see if an exchange actually takes place
                int ThrowDiceXTimes = rDice.Next(1, 3 + 1); // this looks confusing, but makes sense
                                                            // if not an array reference, see above
                for (int j = 0; j < ThrowDiceXTimes; j++)
                {
                    Chance = rChance.Next(1, 100 + 1); // same comment as above, we want a number between 1 and 100
                }

                if (Chance > 50)// 50% chance of an exchange, no bribes will be accepted.
                {// now switch locations
                    bStart = b[StartToSwap];
                    bEnd = b[EndToSwap];
                    b[StartToSwap] = Convert.ToByte(bEnd);
                    b[EndToSwap] = Convert.ToByte(bStart);
                }
            }

            oRNGStartSwap.Dispose();
            oRNGEndSwap.Dispose();
            oRNGDice.Dispose();
            oRNGChance.Dispose();
        }

        public void PopulateSeeds()
        {
            RNGCryptoServiceProvider oRNG = new RNGCryptoServiceProvider();
            {
                byte[] b = GetNxt(oRNG);
                QuantumShuffle(ref b);
                oSeeds.SeedXOR = b;

                b = GetNxt(oRNG);
                QuantumShuffle(ref b);
                oSeeds.SeedNotchPlan = b;

                b = GetNxt(oRNG);
                QuantumShuffle(ref b);
                oSeeds.SeedStartPositions = b;

                b = GetNxt(oRNG);
                QuantumShuffle(ref b);
                oSeeds.SeedTurnOverPositions = b;

                oRNG.Dispose();
            }
        }

        public NoReflectorMode GetCorrectDecodeOpt(NoReflectorMode TargetNode)
        {
            if (oSettings.NoReflectorMode.Equals(NoReflectorMode.Decipher))
            {
                return NoReflectorMode.Encipher;
            }

            if (oSettings.NoReflectorMode.Equals(NoReflectorMode.Encipher))
            {
                return NoReflectorMode.Decipher;
            }

            return TargetNode;
        }

        public CBCMode GetCorrectDecodeOpt(CBCMode cm)
        {
            if (oSettings.CBCMode.Equals(CBCMode.Forward))
            {
                return CBCMode.Reverse;
            }

            if (oSettings.CBCMode.Equals(CBCMode.Reverse))
            {
                return CBCMode.Forward;
            }

            return cm;
        }

        private static byte[] GetNxt(RNGCryptoServiceProvider oRNG)
        {
            byte[] bR = new byte[4];
            oRNG.GetBytes(bR);
            Int32 iDice = BitConverter.ToInt32(bR, 0);
            Random rDice = new Random(iDice);
            // roll the dice up to 7 X to populate bR
            int ThrowDiceXTimes = rDice.Next(1, 7 + 1);
            for (int j = 0; j < ThrowDiceXTimes; j++)
            {
                oRNG.GetBytes(bR);
            }
            return bR;
        }

        private static byte XOR(byte bIn, byte pad)
        {
            int iT = new int();
            iT = bIn ^ pad;
            return (byte)iT;
        }

        public byte[] SecureXOR(byte[] bIn, Seeds oSeeds)
        {
            Random oR = new Random(BitConverter.ToInt32(oSeeds.SeedXOR, 0));
            byte[] pad = new byte[bIn.Length];
            oR.NextBytes(pad);
            return XOR(bIn, pad);
        }
        private byte[] XOR(byte[] bIn, byte[] pad)
        {
            byte[] rtn = new byte[bIn.Length];
            if (pad.Length < bIn.Length)
            {
                return rtn;
            }

            int iT = new int();
            for (int i = 0; i <= bIn.Length - 1; i++)
            {
                iT = bIn[i] ^ pad[i];
                rtn[i] = (byte)iT;
            }

            return rtn;
        }


    }
}