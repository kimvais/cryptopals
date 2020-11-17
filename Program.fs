module Challenges

open System
open Cryptopals.Utils

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


let c1 =
    let input =
        "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"

    input |> readHex |> base64encode |> printfn "%s"
    0

let calculateScore (s: seq<byte>) =
    s |> Seq.map getFrequencyScore |> Seq.sum

let xorWithChar (input: seq<byte>) (x: byte) = input |> Seq.map (fun c -> c ^^^ x)


let c3 input =
    seq { 0uy .. 255uy }
    |> Seq.map (xorWithChar input)
    |> Seq.maxBy calculateScore
    |> Seq.map byteToStr
    |> String.concat ""
    |> printfn "%s"

    0

let getNumber (a: seq<string>): int = a |> Seq.head |> int

let selectChallenge c =
    match c with
    | 1 -> c1
    | 3 ->
        c3
            ("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
             |> readHex)
    | _ -> (0)

[<EntryPoint>]
let main argv = argv |> getNumber |> selectChallenge
