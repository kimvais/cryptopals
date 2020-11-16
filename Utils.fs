module Cryptopals.Utils
open System


let hexToByte (cs: char []) = Convert.ToByte(String(cs), 16)

let readHex input =
    input
    |> Seq.chunkBySize 2
    |> Seq.map hexToByte
    |> Seq.toArray

let base64encode input = Convert.ToBase64String(input)
