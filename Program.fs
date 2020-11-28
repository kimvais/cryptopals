module Challenges

open System
open System.Security.Cryptography
open Cryptopals.Utils
open Cryptopals.Crypto
open Cryptopals.Random


let c1 () =
    let input =
        "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"

    input |> readHex |> base64encode |> printfn "%s"
    0


let c3 () =
    "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    |> readHex
    |> getBestSingleCharXor
    |> bytesToStr
    |> printfn "%s"

    0

let c4 () =
    let lines = readInput 4

    lines
    |> Seq.map (readHex >> getBestSingleCharXor)
    |> Seq.filter (fun s -> (calculateScore s) > float (Seq.length s * 3))
    |> Seq.map bytesToStr
    |> Seq.iter (printfn "%s")

    0

let hammingTuple (a, b) = hamming a b

let hammingByChunk (input: seq<byte>) n =
    let chunks = input |> Seq.chunkBySize n

    let total =
        chunks
        |> Seq.map (fun f -> f |> Seq.ofArray)
        |> Seq.take 4
        |> Seq.pairwise
        |> Seq.map hammingTuple
        |> Seq.sum

    float total / float n

let c6 () =
    let input =
        readInput 6 |> String.Concat |> base64decode

    let keysize =
        seq { 4 .. 40 }
        |> Seq.minBy (hammingByChunk input)

    printf "Key size: %d\n" keysize

    let keybytes =
        input
        |> Seq.chunkBySize keysize
        |> Seq.transpose
        |> Seq.map getSingleCharXorKey

    let key = keybytes |> bytesToStr
    printf "Key: %s\n" key

    let plaintext =
        xorBytes input (key |> generateRepeatingKey)
        |> bytesToStr

    printf "Plaintest:\n%s" plaintext
    0

let c7 () =
    let input =
        readInput 7 |> String.Concat |> base64decode

    let key = keyFromString "YELLOW SUBMARINE"

    let plaintext = decryptECB key input
    printf "Challenge 7 plaintext:\n%s" (bytesToStr plaintext)
    0

let c8 () =
    let lines = readInput 8 |> Seq.map readHex
    let best = lines |> Seq.maxBy (countDuplicates BLOCKSIZE) |> bytesToHexString
    printf "%A" best
    0
   
let c10 () =
    let input = readInput 10 |> String.Concat |> base64decode
    printf "%d\n" <| Seq.length input
    let key = keyFromString "YELLOW SUBMARINE"
    let iv = Array.init 16 (fun _ -> 0uy)
    let plaintext = decryptCBC key input iv |> bytesToStr
    printfn "%s" plaintext
    0
   
let c11 () =
    for inputLen in 37 .. 43 do
        let input = Seq.init inputLen (fun _ -> 65uy)  // A
        seq {
            for _ in 0 .. 10000 do
                let prefixPad = getRandBytes (prng.Next(5, 11))
                let suffixPad = getRandBytes (prng.Next(5, 11))
                let paddedInput = seq {prefixPad; input; suffixPad} |> Seq.concat
                let isReallyECB = coinFlip()
                let mode = match isReallyECB with
                    | true -> ECB
                    | false -> CBC
                let ciphertext = encryptWithRandomKey mode paddedInput
                let blocks = countBlocks BLOCKSIZE ciphertext
                let uniques = countUniques BLOCKSIZE ciphertext
                let wasDetectedECB = uniques < blocks
                yield (isReallyECB, wasDetectedECB)
            } |> Seq.sumBy (fun (a, b) -> match a = b with | false -> 0.0 | true -> 0.01) |> (printfn "%d: %.1f %%"  inputLen)
    0
    
let getNumber (a: seq<string>): int = a |> Seq.head |> int

let selectChallenge =
    function
    | 1 -> c1
    | 3 -> c3
    | 4 -> c4
    | 6 -> c6
    | 7 -> c7
    | 8 -> c8
    | 10 -> c10
    | 11 -> c11
    | _ -> fun () -> -1

[<EntryPoint>]
let main argv =
    let number = argv |> getNumber
    printf "--- Solving challenge %d ---\n" number
    (number |> selectChallenge) ()
