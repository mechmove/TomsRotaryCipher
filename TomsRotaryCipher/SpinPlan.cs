using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using StoneAgeEncryptionService;

namespace RotorSpinPln
{
    class RotorSpinPlan
    {
        protected static long RotorPos = -1;
        protected static string ForTest = String.Empty;
        protected Random r;

        public byte[] GetNotchPlan(NotchPlan notchPlan, int Rotors, long PlainTxtPos,
        int SeedNotchTurnover, ref byte[] eSpinFactor, int Radix)
        {
            byte[] bRtn = new byte[Rotors];
            RotorPos++;

            if (notchPlan.Equals(NotchPlan.HopScotch))
            {// more advanced multiple rotor skipping for n= rotors, how many combinations (sans ALL)

                long TotalCombinations = Rotors;
                for (int i = 2; i < Rotors; i++)
                {
                    TotalCombinations += Supportg.PermutationsAndCombinations.nCr(Rotors, i);
                }

                /* TotalCombinations will be base 10 number (ex. 6 for 3 rotors), 
                 * pick a pseudo-random number from 1 - 6
                 * convert to Binary, 
                 * step those rotors 1 notch.*/

                if (PlainTxtPos.Equals(0))
                {
                    r = new Random(SeedNotchTurnover);
                }
                int Rand = r.Next(1, (int)TotalCombinations + 1); // get random number between 1 and TotalCombinations
                                                                  //Console.Write(Convert.ToString(Rand) + Environment.NewLine) ;
                string bRandStr = Convert.ToString(Rand, 2); // convert to binary string
                for (int i = bRandStr.Length - 1; i >= 0; i--) // populate array for each character
                {
                    bRtn[bRandStr.Length - i - 1] = (byte)Convert.ToInt16(bRandStr.Substring(i, 1));
                }

                if (RotorPos.Equals(Rotors))
                {
                    RotorPos = -1;
                }

                //for (int x = 0; x <= (Rotors - 1); x++)
                //{
                //    ForTest += bRtn[x].ToString();
                //}

                //if (ForTest.Length.Equals(3000))
                //{
                //    string Hash256 = Hashing.sha256.ComputeSha256Hash(ForTest);
                //}
            }

            if (notchPlan.Equals(NotchPlan.Sequential))
            {
                // this is the simple odometer skipping found in the original rotor cipher machines:
                bRtn[0] = (byte)1;
                IncRotorPos(ref eSpinFactor[0], Radix);

                if (((int)eSpinFactor[0]).Equals(0))
                {// now increment other rotors based on Spin Factor:
                    for (int r = 1; r <= (Rotors - 1); r++)
                    {// prior rotor has completed 1 cycle, increment next downstream rotor
                        if (eSpinFactor[r - 1].Equals(0))
                        {// increment this rotor :(
                            bRtn[r] = (byte)1;
                            IncRotorPos(ref eSpinFactor[r], Radix);
                            break;
                        }
                    }
                }

                if (RotorPos.Equals(Rotors))
                {
                    RotorPos = -1;
                }

                //for (int r = 0; r <= (Rotors - 1); r++)
                //{
                //    ForTest += bRtn[r].ToString();
                //}

                //if (ForTest.Length.Equals(4482))
                //{
                //    string Hash256 = Hashing.sha256.ComputeSha256Hash(ForTest);
                //}
            }
            return bRtn;
        }
        static string ForTestingOnly(int[,] NotchTurnoverPlan, long PlainTxtLen)
        {// this takes forever to run, is used to verify if any changes affect the original NotchTurnoverPlan logic.
            long dim = NotchTurnoverPlan.Length / PlainTxtLen;
            string ForHashing = string.Empty;
            for (long i = 0; i < PlainTxtLen; i++)
            {
                for (long k = 0; k < dim; k++)
                {
                    ForHashing += NotchTurnoverPlan[i, k];
                }
            }
            int HashLen = ForHashing.Length;
            return Hashing.sha256.ComputeSha256Hash(ForHashing);
        }
        static void IncRotorPos(ref byte b, int Radix)
        {
            int i = (int)b;
            i++;
            if (i > (Radix - 1)) { i = 0; }
            b = (byte)i;
        }
    }
}

