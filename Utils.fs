module Cryptopals.Utils

open System
open System.IO
open System.Security.Cryptography


let readLines filePath = File.ReadLines(filePath)

let readInput (n: int) =
    readLines (__SOURCE_DIRECTORY__ + (sprintf "/data/%d.txt" n))

let hexToByte (cs: char []) = Convert.ToByte(String(cs), 16)
let byteToHex (b: byte) = b.ToString("x2")

let readHex input =
    input
    |> Seq.chunkBySize 2
    |> Seq.map hexToByte
    |> Seq.toArray

let base64encode input = Convert.ToBase64String(input)

let base64decode input = Convert.FromBase64String(input)


let byteToStr b = string (char (b))

let getFrequencyScore l =
    let upper = Char.ToUpper(char (l))

    match upper with
    | 'A' -> 8.4966
    | 'B' -> 2.0720
    | 'C' -> 4.5388
    | 'D' -> 3.3844
    | 'E' -> 11.1607
    | 'F' -> 1.8121
    | 'G' -> 2.4705
    | 'H' -> 3.0034
    | 'I' -> 7.5448
    | 'J' -> 0.1965
    | 'K' -> 1.1016
    | 'L' -> 5.4893
    | 'M' -> 3.0129
    | 'N' -> 6.6544
    | 'O' -> 7.1635
    | 'P' -> 3.1671
    | 'Q' -> 0.1962
    | 'R' -> 7.5809
    | 'S' -> 5.7351
    | 'T' -> 6.9509
    | 'U' -> 3.6308
    | 'V' -> 1.0074
    | 'W' -> 1.2899
    | 'X' -> 0.2902
    | 'Y' -> 1.7779
    | 'Z' -> 0.2722
    | ' ' -> 6.0
    | '.'
    | ','
    | '''
    | '?'
    | '!' -> 0.0
    | _ -> -10.0

let hexToString (bytes: byte []): string =
    bytes |> Seq.map byteToHex |> String.concat ""

let calculateScore (s: seq<byte>) =
    s |> Seq.map getFrequencyScore |> Seq.sum

let xorWithChar (input: seq<byte>) (x: byte) = input |> Seq.map (fun c -> c ^^^ x)


let bytesToStr (bs: seq<byte>) =
    bs |> Seq.map byteToStr |> String.concat ""

let getBestSingleCharXor input =
    seq { 0uy .. 255uy }
    |> Seq.map (xorWithChar input)
    |> Seq.maxBy calculateScore

let getSingleCharXorKey input =
    seq { 0uy .. 255uy }
    |> Seq.maxBy (fun f -> xorWithChar input f |> calculateScore)

let getRepeatingKey (input: string) (index: int) = input.[index % input.Length] |> byte

let generateRepeatingKey input = Seq.initInfinite (getRepeatingKey input)

let asBitStr (number: byte) = Convert.ToString(number, 2)

let xorTuple (a, b) = a ^^^ b

let matchOne c =
    match c with
    | '1' -> true
    | _ -> false

let countOnes s = s |> Seq.filter matchOne |> Seq.length

let xorBytes key input = Seq.zip input key |> Seq.map xorTuple

let hamming one other =
    Seq.zip one other
    |> Seq.map (xorTuple >> asBitStr >> countOnes)
    |> Seq.sum

let bytesToHexString bs =
    bs |> Seq.map byteToHex |> String.concat ""

let AESDecrypt (mode: CipherMode) (key: byte []) (ciphertext: byte []) =
    use aes = Aes.Create()
    aes.Mode <- mode
    aes.Key <- key
    let decryptor = aes.CreateDecryptor()
    use cipherStream = new MemoryStream(ciphertext)

    use decryptionStream =
        new CryptoStream(cipherStream, decryptor, CryptoStreamMode.Read)

    use plainStream = new StreamReader(decryptionStream)
    plainStream.ReadToEnd()

let pkcs7pad (size: int) (input: seq<byte>) =
    let padlen = size - Seq.length input % size

    let padding =
        Seq.init padlen (fun _ -> byte padlen)

    Seq.concat [ input; padding ]
