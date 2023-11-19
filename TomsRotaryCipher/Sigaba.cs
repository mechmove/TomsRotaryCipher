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
            if (notchPlan.Equals(NotchPlan.Sigaba))

            {
                // original Sigaba skipping, more advanced multiple rotor skipping
                // for n= rotors, how many combinations (sans ALL)

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
                {
                    //increment innermost Rotor (1) all the time:
                    // (Note, only Side 1 of double sided rotor moves, 
                    // Side 0 always remains constant)
                    bool PreviousMaxValue = false;
                    NotchTurnoverPlan[l, 0] = (byte)1;
                    IncRotorPos(ref eSpinFactor[0], Radix);

                    int sFc = (int)eSpinFactor[0];
                    if (sFc.Equals(0)) { PreviousMaxValue = true; }

                    // now increment other rotors based on Spin Factor:
                    for (int r = 1; r <= eSpinFactor.Length - 1; r++)
                    {
                        // prior rotor has completed 1 cycle, increment next downstream rotor
                        if (eSpinFactor[r - 1].Equals(0) && PreviousMaxValue)
                        {// increment this rotor!
                            PreviousMaxValue = false;

                            NotchTurnoverPlan[l, r] = (byte)1;
                            IncRotorPos(ref eSpinFactor[r], Radix);

                            sFc = (int)eSpinFactor[r];
                            if (sFc.Equals(0)) { PreviousMaxValue = true; }
                        }
                    }

                }


            }

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

