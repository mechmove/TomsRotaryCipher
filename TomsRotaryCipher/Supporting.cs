using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace Supportg
{
    class Supporting
    {

        public static byte[] XOR(byte[] bIn, byte[] pad)
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

        public static byte XOR(byte bIn, byte pad)
        {
            int iT = new int();
            iT = bIn ^ pad;
            return (byte)iT;
        }


    }

    // "Combinations" code copied from Stack Exchange
    public static class PermutationsAndCombinations
    {
        public static long nCr(int n, int r)
        {
            // naive: return Factorial(n) / (Factorial(r) * Factorial(n - r));
            return nPr(n, r) / Factorial(r);
        }

        public static long nPr(int n, int r)
        {
            // naive: return Factorial(n) / Factorial(n - r);
            return FactorialDivision(n, n - r);
        }

        private static long FactorialDivision(int topFactorial, int divisorFactorial)
        {
            long result = 1;
            for (int i = topFactorial; i > divisorFactorial; i--)
                result *= i;
            return result;
        }

        private static long Factorial(int i)
        {
            if (i <= 1)
                return 1;
            return i * Factorial(i - 1);
        }
    }

}
