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
        public void GetNotchPlan(NotchPlan notchPlan, int Rotors, long PlainTxtLen, byte[] PlainTxt,
            int SeedNotchTurnover, byte[] eSpinFactor, int Radix, ref int[,] NotchTurnoverPlan)
        {
            if (notchPlan.Equals(NotchPlan.HopScotch))
            {
                // more advanced multiple rotor skipping for n= rotors, how many combinations (sans ALL)

                long TotalCombinations = Rotors;
                for (int i = 2; i < Rotors; i++)
                {
                    TotalCombinations += Supportg.PermutationsAndCombinations.nCr(Rotors, i);
                }

                /* TotalCombinations will be base 10 number (ex. 6 for 3 rotors), 
                 * pick a pseudo-random number from 1 - 6
                 * convert to Binary, 
                 * step those rotors 1 notch.*/

                Random r = new Random(SeedNotchTurnover);
                NotchTurnoverPlan = new int[PlainTxtLen, Rotors];
                for (long l = 0; l <= PlainTxtLen - 1; l++)
                {
                    int Rand = r.Next(1, (int)TotalCombinations + 1); // get random number between 1 and TotalCombinations
                                                                      //Console.Write(Convert.ToString(Rand) + Environment.NewLine) ;
                    string bRandStr = Convert.ToString(Rand, 2); // convert to binary string
                    for (int i = bRandStr.Length - 1; i >= 0; i--) // populate array for each character
                    {
                        NotchTurnoverPlan[l, bRandStr.Length - i - 1] = Convert.ToInt16(bRandStr.Substring(i, 1));
                    }
                }
            }

            if (notchPlan.Equals(NotchPlan.Sequential))
            {
                // this is the simple odometer skipping found in the original rotor cipher machines:
                NotchTurnoverPlan = new int[PlainTxtLen, Rotors];
                for (long l = 0; l <= PlainTxtLen - 1; l++)
                {//increment innermost Rotor (1) all the time:
                 // (Note, only Side 1 of double sided rotor moves, 
                 // Side 0 always remains constant)
                    NotchTurnoverPlan[l, 0] = (byte)1;
                    IncRotorPos(ref eSpinFactor[0], Radix);

                    if (((int)eSpinFactor[0]).Equals(0)) 
                    {// now increment other rotors based on Spin Factor:
                        for (int r = 1; r <= eSpinFactor.Length - 1; r++)
                        {// prior rotor has completed 1 cycle, increment next downstream rotor
                            if (eSpinFactor[r - 1].Equals(0))
                            {// increment this rotor :(
                                NotchTurnoverPlan[l, r] = (byte)1;
                                IncRotorPos(ref eSpinFactor[r], Radix);
                                break;
                            }
                        }
                    }
                }
                // ForTestingOnly() produces a hash of NotchTurnoverPlan[,] 
                // which is required when making changes to GetNotchPlan(), 
                // first get a hash of the original logic, then compare to hash
                // of new logic, they should match. DO NOT LEAVE UNCOMMENTED!
                // This code is HIGHLY inefficient, and slows down performance. 
                
                //string HashForTestOnly = ForTestingOnly(NotchTurnoverPlan, PlainTxtLen);
            }

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

