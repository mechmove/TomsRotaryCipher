using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace StoneAgeEncryptionService
{
    public enum EnigmaMode { WithReflector, NoReflector }
    public enum NoReflectorMode { None, Forward, Reverse }
    public enum NotchPlan { Sequential, Sigaba, SigabaEcono_OTP }
    public enum CBCMode { None, Forward, Reverse }

    public class TomsRotaryCipher
    {
        public class Seeds
        {
            public byte[] SeedXOR { get; set; }
            public byte[] SeedRotors { get; set; }
            public byte[] SeedNotchPlan { get; set; }
            public byte[] SeedTurnOverPositions { get; set; }
            public byte[] SeedStartPositions { get; set; }
            public byte[] SeedPlugBoard { get; set; }
            public byte[] SeedReflector { get; set; }
        }

        public class Settings
        {
            public int MovingCipherRotors { get; set; }
            public NotchPlan NotchPlan { get; set; }
            public EnigmaMode EnigmaMode { get; set; }
            public NoReflectorMode NoReflectorMode { get; set; }
            public CBCMode CBCMode { get; set; }
        }

        protected static long HighestIteration;// for analysis
        protected int TotalRotors { get { return 2 + oSettings.MovingCipherRotors; } set { } }  // MovingCipherRotors + 2; // need plugboard and reflector

        public Seeds oSeeds = new Seeds();
        public Settings oSettings = new Settings();

        public byte[] SAES(NotchPlan np, byte[] UserStr,
            EnigmaMode em,
            NoReflectorMode nrm,
            CBCMode cm = CBCMode.None)
        {

            const int sides = 2;
            const int radix = 256;
            const int randomMultiplier = 20;

            if (oSeeds.SeedNotchPlan is null)
            {
                throw new Exception("Please PopulateSeeds or LoadAll!");
            }

            oSettings.CBCMode = cm;
            oSettings.NotchPlan = np;
            int movingCipherRotors = oSettings.MovingCipherRotors;

            byte[,,] e = CreateMachine(TotalRotors, sides, radix);
            PopulateRotors(ref e, BitConverter.ToInt32(oSeeds.SeedRotors, 0), radix, randomMultiplier, TotalRotors, sides);

            // make a local copy for speed optimization
            byte[] eSpinFactor = new byte[TotalRotors - 2];
            int[,] notchTurnoverPlan = new int[0, 0];

            AssignTurnOverPositions(ref eSpinFactor, BitConverter.ToInt32(oSeeds.SeedTurnOverPositions, 0));

            RotorSpinPln.RotorSpinPlan oSig = new RotorSpinPln.RotorSpinPlan();
            oSig.GetNotchPlan(np, movingCipherRotors, UserStr.Length, UserStr, BitConverter.ToInt32(oSeeds.SeedNotchPlan, 0),
            eSpinFactor, radix, ref notchTurnoverPlan);

            byte[] eStartPositions = new byte[TotalRotors - 2];
            AssignStartPositions(ref eStartPositions, BitConverter.ToInt32(oSeeds.SeedStartPositions, 0));
            ConfigureStartPositions(eStartPositions, radix, TotalRotors, ref e);
            CreatePlugBoard(ref e, BitConverter.ToInt32(oSeeds.SeedPlugBoard, 0), radix, randomMultiplier);
            CreateReflector(ref e, BitConverter.ToInt32(oSeeds.SeedReflector, 0), radix, randomMultiplier);

            oSettings.MovingCipherRotors = movingCipherRotors;
            oSettings.EnigmaMode = em;
            oSettings.NoReflectorMode = nrm;

            // make a local copy of property for speed optimization
            byte[] eVirtualRotorMove = new byte[movingCipherRotors];
            int totalRotors = TotalRotors;

            ConfigureRevLookUps(radix, totalRotors, ref e);

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

                if (em.Equals(EnigmaMode.WithReflector))
                {
                    // take it through PlugBoard, all rotors, and  reflector
                    for (int r = 0; r <= totalRotors - 1; r++)
                    {
                        Transform = ByteLookup(Transform, r, radix, totalRotors, e, eVirtualRotorMove);
                    }

                    // now backwards through rotors and plugboard
                    for (int r = totalRotors - 2; r >= 0; r--)
                    {
                        Transform = ByteLookupRev(Transform, r, radix, totalRotors, e, eVirtualRotorMove);
                    }
                }
                else
                {
                    if (nrm.Equals(NoReflectorMode.Forward))
                    {
                        // take it through PlugBoard, all rotors
                        for (int r = 0; r <= totalRotors - 2; r++)
                        {
                            Transform = ByteLookup(Transform, r, radix, totalRotors, e, eVirtualRotorMove);
                        }
                    }
                    if (nrm.Equals(NoReflectorMode.Reverse))
                    {
                        // now backwards through rotors and plugboard
                        for (int r = totalRotors - 2; r >= 0; r--)
                        {
                            Transform = ByteLookupRev(Transform, r, radix, totalRotors, e, eVirtualRotorMove);
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

                if (np.Equals(NotchPlan.Sigaba))
                {
                    // spin rotors based on notch plan
                    for (int r = 1; r <= totalRotors - 2; r++)
                    {
                        if (notchTurnoverPlan[i, r - 1].Equals(1))
                        {
                            MoveArrayPointerMainRotors(r, 1, radix, ref eVirtualRotorMove);
                        }
                    }
                }
                if (np.Equals(NotchPlan.Sequential))
                {
                    // spin rotors, notchplan is not needed, creates "out of memory" 
                    // with a very large number of rotors.
                    for (int r = 1; r <= totalRotors - 2; r++)
                    {
                        if (r.Equals(1))
                        {
                            MoveArrayPointerMainRotors(r, 1, radix, ref eVirtualRotorMove);
                        }
                    }
                }
            }
            return Rtn;
        }

        private byte ByteLookupRev(byte currentByte, int Rotor, int Radix, int TotalRotors, byte[,,] e, byte[] eVirtualRotorMove)
        {
            if (Rotor.Equals(0)) // reflector never goes backwards
            {
                return (byte)e[Rotor, 0, currentByte];
            }
            else
            {
                int OffsetTst = e[Rotor, 0, currentByte] - eVirtualRotorMove[Rotor - 1];
                return (byte)OffsetTst;
            }
        }

        private byte ByteLookup(byte currentByte, int Rotor, int Radix, int TotalRotors, byte[,,] e, byte[] eVirtualRotorMove)
        {
            if (Rotor.Equals(0) || (Rotor.Equals(TotalRotors - 1)))
            {
                return e[Rotor, 1, currentByte];
            }
            else
            {
                int Offset = eVirtualRotorMove[Rotor - 1] + currentByte;
                if (Offset >= Radix)
                {
                    Offset = Offset - Radix;
                }
                return e[Rotor, 1, Offset];
            }
        }

        private void ConfigureStartPositions(byte[] eStartPositions, int Radix, int Rotors, ref byte[,,] e)
        {
            for (int i = 1; i <= Rotors - 2; i++)
            {
                MoveArrayPointer(i, eStartPositions[i - 1], Radix, ref e);
            }
        }

        private void ConfigureRevLookUps(int Radix, int Rotors, ref byte[,,] e)
        {
            // populate Main Rotors side 0 with inverse of side 1 for quick reverse lookups
            for (int iRotor = 1; iRotor <= Rotors - 2; iRotor++)
            {
                for (int Col = 0; Col <= (Radix - 1); Col++)
                {
                    e[iRotor, 0, e[iRotor, 1, Col]] = (byte)Col;
                }
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


        private void MoveArrayPointer(int Row, int eStartPosition, int Radix, ref byte[,,] e)
        {
            byte[] bAP = new byte[Radix];
            for (int i = 0; i <= Radix - 1; i++)
            {
                bAP[i] = e[Row, 1, i];
            }
            for (int i = 0; i <= (Radix - 1); i++)
            {
                e[Row, 1, i] = bAP[eStartPosition];
                eStartPosition++;
                if (eStartPosition > (Radix - 1))
                {
                    eStartPosition = 0;
                }
            }
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

        private void CreatePlugBoard(ref byte[,,] b, int Seed, int radix, int randomMultiplier)
        { // re-create this rotor with seed for more variance:
            byte[,,] bSource = CreateMachine(1, 2, radix);
            byte[,,] bHolding = CreateMachine(1, 2, radix);
            PopulateRotors(ref bSource, Seed, radix, randomMultiplier, 1, 2);

            for (int iBinaryPos = 0; iBinaryPos <= (radix - 1); iBinaryPos++)
            {
                bHolding[0, 0, iBinaryPos] = bSource[0, 0, iBinaryPos];
                bHolding[0, 1, iBinaryPos] = bSource[0, 1, iBinaryPos];
            }

            /* PlugBoard : igousbtrcpnmefwhqlkavzdyxj
             * PlugBoard : giuobsrtpcmnfehwlqakzvydjx*/
            for (int iBinaryPos = 0; iBinaryPos <= (radix - 2); iBinaryPos += 2)
            {
                bHolding[0, 1, iBinaryPos] = bHolding[0, 0, iBinaryPos + 1];
                bHolding[0, 1, iBinaryPos + 1] = bHolding[0, 0, iBinaryPos];
            }

            // now update b
            for (int iCol = 0; iCol <= (radix - 1); iCol++)
            {
                b[0, 0, bHolding[0, 0, iCol]] = bHolding[0, 1, iCol];
                b[0, 1, bHolding[0, 1, iCol]] = bHolding[0, 0, iCol];
            }
        }

        private void CreateReflector(ref byte[,,] b, int Seed, int radix, int randomMultiplier)
        {// re-create this rotor with seed for more variance:
            byte[,,] bSource = CreateMachine(1, 2, radix);
            byte[,,] bHolding = CreateMachine(1, 2, radix);
            PopulateRotors(ref bSource, Seed, radix, randomMultiplier, 1, 2);

            for (int iBinaryPos = 0; iBinaryPos <= (radix - 1); iBinaryPos++)
            {
                bHolding[0, 0, radix - iBinaryPos - 1] = bSource[0, 0, iBinaryPos];
                bHolding[0, 1, radix - iBinaryPos - 1] = bSource[0, 1, iBinaryPos];
            }

            /*     
            Reflector : phafjdsilcebguwyvkotqzmxrn
            Reflector : nrxmzqtokvywugbeclisdjfahp*/
            int Query = radix - 1;
            for (int iBinaryPos = 0; iBinaryPos <= (radix) - 1; iBinaryPos++)
            {
                bHolding[0, 1, (radix - iBinaryPos - 1)] = bHolding[0, 0, iBinaryPos];
            }

            // now update b
            for (int iCol = 0; iCol <= (radix - 1); iCol++)
            {
                b[TotalRotors - 1, 0, bHolding[0, 0, iCol]] = bHolding[0, 1, iCol];
                b[TotalRotors - 1, 1, bHolding[0, 1, iCol]] = bHolding[0, 0, iCol];
            }
        }


        private byte[,,] CreateMachine(int numRotors, int Sides, int Radix)
        {
            byte[,,] e = new byte[numRotors, Sides, Radix];
            return e;
        }
        private void PopulateRotors(ref byte[,,] b, int iSeed, int Radix, int RandomMultiplier, int Rotors, int Sides)
        {
            System.Random oRandom = new System.Random(iSeed);
            long RandomArraySize = Radix * Rotors * RandomMultiplier;
            // apparently, max value of byte array is 2,130,702,268 slightly less than 2,147,483,647 for int32
            if (RandomArraySize>2130702268)
            {// this won't work, get OUT!
                string err = "RandomArraySize: " + RandomArraySize.ToString() + " is greater than range of INT!" + Environment.NewLine + Environment.NewLine;
                System.IO.File.WriteAllText("error.txt", err);
                Console.WriteLine(err);
                Console.ReadKey();
                throw new InvalidOperationException(err);
            }
            byte[] bNext = new byte[RandomArraySize]; // Need unique numbers only, this is the available pool, larger than required
            long ArrayCnt = 0;
            oRandom.NextBytes(bNext);


            for (int iRotor = 0; iRotor <= Rotors - 1; iRotor++)
            {
                for (int iSide = 0; iSide <= (Sides - 1); iSide++)
                {
                    bool PopulateSide0 = false;
                    if ((iRotor.Equals(0) || iRotor.Equals(Rotors - 1)) && iSide.Equals(0))
                    {
                        PopulateSide0 = true;
                    }

                    if (!PopulateSide0 && iSide.Equals(0))
                    { }
                    else
                    {
                        byte[] bUnique = GetUnique(ref ArrayCnt, bNext, Radix, RandomMultiplier, RandomArraySize);
                        for (int iBinaryPos = 0; iBinaryPos <= Radix - 1; iBinaryPos++)
                        {
                            b[iRotor, iSide, iBinaryPos] = bUnique[iBinaryPos];
                        }

                    }

                }
            }
        }

        private byte[] GetUnique(ref long ArrayCnt, byte[] bRandomNums, int Radix, int RandomMultiplier, long RandomArraySize)
        {
            bool ZeroInserted = false;
            byte[] bUnique = new byte[Radix];
            int iCurrentPosUnique = 0;
            for (long iRandomPos = ArrayCnt; iRandomPos <= RandomArraySize - 1; iRandomPos++)
            {
                if (!iCurrentPosUnique.Equals(Radix))
                {
                    InsertUnique(ref bUnique, ref iCurrentPosUnique, bRandomNums[iRandomPos], ref ZeroInserted);
                }
                else
                {
                    ArrayCnt = iRandomPos;
                    if (iRandomPos > HighestIteration) // for Analysis
                    {
                        HighestIteration = iRandomPos;
                    }
                    iRandomPos = RandomArraySize;// force exit, all numbers filled
                }
            }
            return bUnique;
        }

        private void InsertUnique(ref byte[] bUnique, ref int iCurrentPosUnique, byte DataToInsert, ref bool ZeroInserted)
        {
            bool bInsert = true;
            for (int iUniquePos = 0; iUniquePos <= iCurrentPosUnique; iUniquePos++)
            {
                if (bUnique[iUniquePos].Equals(DataToInsert))
                {
                    if (!DataToInsert.Equals(0))
                    {
                        bInsert = false;
                        iUniquePos = iCurrentPosUnique;
                    }
                    else
                    {
                        if (!iUniquePos.Equals(iCurrentPosUnique))
                        {
                            bInsert = false;
                            iUniquePos = iCurrentPosUnique;
                        }
                    }
                }
            }
            if (bInsert)
            {
                if (DataToInsert.Equals(0)) { ZeroInserted = true; }
                // if insert, then increment 
                bUnique[iCurrentPosUnique] = DataToInsert;
                iCurrentPosUnique++;
            }
        }

        public void PopulateSeeds(
            byte[] bSeedXOR,
            byte[] bSeedRotors,
            byte[] bSeedNotchPlan,
            byte[] bSeedTurnOverPositions,
            byte[] bSeedStartPositions,
            byte[] bSeedPlugBoard,
            byte[] bSeedReflector)
        {
            // these are used for regression testing
            oSeeds.SeedXOR = bSeedXOR;
            oSeeds.SeedNotchPlan = bSeedNotchPlan;
            oSeeds.SeedPlugBoard = bSeedPlugBoard;
            oSeeds.SeedReflector = bSeedReflector;
            oSeeds.SeedRotors = bSeedRotors;
            oSeeds.SeedStartPositions = bSeedStartPositions;
            oSeeds.SeedTurnOverPositions = bSeedTurnOverPositions;
        }

        public byte[] GetAll()
        {
            return GetSeeds().Concat(GetSettings()).ToArray();
        }

        private byte[] GetSeeds()
        {
            return oSeeds.SeedXOR.Concat(oSeeds.SeedNotchPlan).Concat(oSeeds.SeedPlugBoard).Concat(oSeeds.SeedReflector).Concat(oSeeds.SeedRotors).Concat(oSeeds.SeedStartPositions).Concat(oSeeds.SeedTurnOverPositions).ToArray();
        }

        private byte[] GetSettings()
        {
            byte[] bRotors = BitConverter.GetBytes(oSettings.MovingCipherRotors);
            byte[] bNotchPlan = BitConverter.GetBytes(Convert.ToInt16(oSettings.NotchPlan));
            byte[] bEnigmaMode = BitConverter.GetBytes(Convert.ToInt16(oSettings.EnigmaMode));
            byte[] bNoReflectorMode = BitConverter.GetBytes(Convert.ToInt16(oSettings.NoReflectorMode));
            byte[] bCBCMode = BitConverter.GetBytes(Convert.ToInt16(oSettings.CBCMode));
            return bRotors.Concat(bNotchPlan).Concat(bEnigmaMode).Concat(bNoReflectorMode).Concat(bCBCMode).ToArray();
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
            oSeeds.SeedPlugBoard = newArray;
            i += 4;

            newArray = b.Skip(i).Take(4).ToArray();
            oSeeds.SeedReflector = newArray;
            i += 4;

            newArray = b.Skip(i).Take(4).ToArray();
            oSeeds.SeedRotors = newArray;
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
            oSettings.EnigmaMode = (EnigmaMode)BitConverter.ToInt16(newArray, 0);
            i += 2;

            newArray = b.Skip(i).Take(2).ToArray();
            oSettings.NoReflectorMode = (NoReflectorMode)BitConverter.ToInt16(newArray, 0);
            i += 2;

            newArray = b.Skip(i).Take(2).ToArray();
            oSettings.CBCMode = (CBCMode)BitConverter.ToInt16(newArray, 0);

        }


        public void PopulateSeeds()
        {
            RNGCryptoServiceProvider oRNG = new RNGCryptoServiceProvider();
            {
                oSeeds.SeedXOR = GetNxt(oRNG);
                oSeeds.SeedNotchPlan = GetNxt(oRNG);
                oSeeds.SeedPlugBoard = GetNxt(oRNG);
                oSeeds.SeedReflector = GetNxt(oRNG);
                oSeeds.SeedRotors = GetNxt(oRNG);
                oSeeds.SeedStartPositions = GetNxt(oRNG);
                oSeeds.SeedTurnOverPositions = GetNxt(oRNG);
            };
        }

        public NoReflectorMode GetCorrectDecodeOpt(NoReflectorMode TargetNode)
        {
            if (oSettings.NoReflectorMode.Equals(NoReflectorMode.Reverse))
            {
                return NoReflectorMode.Forward;
            }

            if (oSettings.NoReflectorMode.Equals(NoReflectorMode.Forward))
            {
                return NoReflectorMode.Reverse;
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