//
// aPLib compression library  -  the smaller the better :)
//
// C# example
//
// Copyright (c) 1998-2009 by Joergen Ibsen / Jibz
// All Rights Reserved
//
// http://www.ibsensoftware.com/
//

using System;
using System.IO;

using IbsenSoftware.aPLib;

class appack
{
    static int ShowProgress(int length, int slen, int dlen, int cbparam)
    {
        Console.Write("{0} -> {1}\r", slen, dlen);
        return 1;
    }

    static void CompressStream(Stream from, Stream to)
    {
        byte[] src = new byte[from.Length];

        // read file
        if (from.Read(src, 0, src.Length) == src.Length)
        {
            int dstSize = DllInterface.aP_max_packed_size(src.Length);
            int wrkSize = DllInterface.aP_workmem_size(src.Length);

            // allocate mem
            byte[] dst = new byte[dstSize];
            byte[] wrk = new byte[wrkSize];

            // compress data
            int packedSize = DllInterface.aPsafe_pack(
                src,
                dst,
                src.Length,
                wrk,
                new DllInterface.CompressionCallback(ShowProgress),
                0
            );

            // write compressed data
            to.Write(dst, 0, packedSize);

            Console.WriteLine("compressed to {0} bytes", packedSize);
        }
    }

    static void DecompressStream(Stream from, Stream to)
    {
        byte[] src = new byte[from.Length];

        // read file
        if (from.Read(src, 0, src.Length) == src.Length)
        {
            int dstSize = DllInterface.aPsafe_get_orig_size(src);

            // allocate mem
            byte[] dst = new byte[dstSize];

            // decompress data
            int depackedSize = DllInterface.aPsafe_depack(src, src.Length, dst, dstSize);

            // write compressed data
            to.Write(dst, 0, depackedSize);

            Console.WriteLine("decompressed to {0} bytes", depackedSize);
        }
    }

    public static void Main(string[] args)
    {
        Console.WriteLine("===============================================================================");
        Console.WriteLine("aPLib example in C#             Copyright (c) 1998-2009 by Joergen Ibsen / Jibz");
        Console.WriteLine("                                                            All Rights Reserved\n");
        Console.WriteLine("                                                  http://www.ibsensoftware.com/");
        Console.WriteLine("===============================================================================\n");

        if ((args.Length != 3) || ((args[0] != "c") && (args[0] != "d")))
        {
            Console.WriteLine("Syntax:  appack <c|d> <input file> <output file>");
            return;
        }

        string inFilename = args[1];
        string outFilename = args[2];

        if (!File.Exists(inFilename))
        {
            Console.WriteLine("Error: unable to find file '{0}'", inFilename);
            return;
        }

        try {

            using (FileStream inFile  = File.OpenRead(inFilename),
                              outFile = File.Create(outFilename))
            {
                if (args[0] == "c")
                {
                    CompressStream(inFile, outFile);
                } else {
                    DecompressStream(inFile, outFile);
                }
            }

        } catch (Exception e) {

            Console.WriteLine("Error: {0}", e.ToString());
        }
    }
}
