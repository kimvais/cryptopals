module Cryptopals.Crypto

open System.IO
open System.Runtime.InteropServices
open System.Security.Cryptography
open Cryptopals.Utils

[<Literal>]
let BLOCKSIZE = 16

let pkcs7pad (size: int) (input: seq<byte>) =
    let padlen = size - Seq.length input % size

    let padding = Seq.init padlen (fun _ -> byte padlen)

    Seq.concat [ input; padding ]

let pkcs7unpad (input: seq<byte>) =
    let padlen = Seq.last input |> int
    input |> Seq.truncate (Seq.length input - padlen)
    
let aesAlg (key: seq<byte>) =
    let aes = new AesCryptoServiceProvider()
    aes.Mode <- CipherMode.ECB
    aes.Key <- key |> Array.ofSeq
    aes.Padding <- PaddingMode.None
    aes

let getDecryptor key =
    use aes = aesAlg key
    aes.CreateDecryptor()

let getEncryptor key =
    use aes = aesAlg key
    aes.CreateEncryptor()

let encrypt (block: seq<byte>) key =
    let encryptor = getEncryptor key
    let output = Array.create BLOCKSIZE 0uy

    encryptor.TransformBlock((block |> Array.ofSeq), 0, BLOCKSIZE, output, 0)
    |> ignore

    output |> Seq.ofArray

let decrypt (block: seq<byte>) key =
    let decryptor = getDecryptor key
    let output = Array.create BLOCKSIZE 0uy

    decryptor.TransformBlock((block |> Array.ofSeq), 0, BLOCKSIZE, output, 0)
    |> ignore

    output |> Seq.ofArray

let decryptECB key input =
    input
    |> Seq.chunkBySize BLOCKSIZE
    |> Seq.map (fun b -> decrypt b key)
    |> Seq.concat

let encryptCBC key input iv =
    let mutable prevBlock = iv

    seq {
        for block in (pkcs7pad BLOCKSIZE input)
                     |> Seq.chunkBySize BLOCKSIZE do
            let xorredBlock = xorBytes prevBlock block
            let cipherBlock = encrypt xorredBlock key
            prevBlock <- cipherBlock
            yield! cipherBlock
    }

let decryptCBC key input (iv:seq<byte>) =
    let mutable prevBlock = iv

    seq {
        for block in input |> Seq.chunkBySize BLOCKSIZE do
            let plainblock = decrypt block key
            let plaintext = xorBytes prevBlock plainblock
            prevBlock <- block
            yield! plaintext
    }
