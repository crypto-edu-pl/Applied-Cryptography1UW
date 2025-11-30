# Coding Challenge #1

Solutions by Michał Racinowski (450260)

The workspace contains three crates with solutions to the challenges.

## CBC mode encryption (10; easy)

To decrypt the file from the challenge execute:

```
cargo run --bin=easy decrypt "YELLOW SUBMARINE" "0000000000000000" easy/10.txt
```

The package also allows for encryption:

```
cargo run --bin=easy encrypt "YELLOW SUBMARINE" "0000000000000000" easy/ptx.txt
```

Usage of the package is available with command:

```
cargo run --bin=easy
```

## CBC bitflipping attack (16; medium)

To run the attack execute:

```
cargo run --bin=medium
```

## CBC padding oracle attack (17; hard)

To run the solution execute:

```
cargo run --bin=hard
```

It is also possible to run the challenge on provided plaintext:

```
cargo run --bin=hard 'Hello world!'
```
