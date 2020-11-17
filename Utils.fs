module Cryptopals.Utils

open System


let readLines filePath = System.IO.File.ReadLines(filePath)

let readInput (n:int) = readLines (sprintf "data/%d.txt" n)

let hexToByte (cs: char []) = Convert.ToByte(String(cs), 16)
let byteToHex (b: byte) = b.ToString("x2")

let readHex input =
    input
    |> Seq.chunkBySize 2
    |> Seq.map hexToByte
    |> Seq.toArray

let base64encode input = Convert.ToBase64String(input)

let hexToString (bytes: byte []): string =
    bytes |> Seq.map byteToHex |> String.concat ""
