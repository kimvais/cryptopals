module Challenges

open System
open Cryptopals.Utils


let c1 =
    let input =
        "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"

    input |> readHex |> base64encode |> printfn "%s"
    0


let c3 =
    "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    |> readHex
    |> getBestSingleCharXor
    |> bytesToStr
    |> printfn "%s"

    0

let c4 =
    let lines = readInput 4

    lines
    |> Seq.map (readHex >> getBestSingleCharXor)
    |> Seq.filter (fun s -> (calculateScore s) > float (Seq.length s * 3))
    |> Seq.map bytesToStr
    |> Seq.iter (printfn "%s")

    0

let getNumber (a: seq<string>): int = a |> Seq.head |> int

let selectChallenge c =
    printfn "Solving challenge %d" c

    match c with
    | 1 -> c1
    | 3 -> c3
    | 4 -> c4
    | _ -> (0)

[<EntryPoint>]
let main = getNumber >> selectChallenge
