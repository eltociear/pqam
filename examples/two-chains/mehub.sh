#!/usr/bin/env bash
# A private single-node ME Hub for the pqam two-chain example. Its own data dir (./mehub-home) and its
# own ports (46xxx), so it never touches another local node (Leash ID's devnet uses 36657/1317) or the
# public testnet. Built from openmetaearth/me-hub; uses that repo's public dev keys (`user` is funded).
#   ./mehub.sh init <addresses.json>   fresh chain; DIDs from the file go into the x/did genesis
#   ./mehub.sh start | stop
#   ./mehub.sh fund <address> <umec>
set -euo pipefail
D="$(cd "$(dirname "$0")" && pwd)"
HUB="${ME_HUB_DIR:-$HOME/workspace/harbor/vendor/me-hub}"
# Run a private copy of the binary: other tools stop their node with `pkill -f "$HUB/build/med start"`,
# which would match ours too.
MED="$D/.bin/med"
mkdir -p "$D/.bin" && { cmp -s "$HUB/build/med" "$MED" || cp "$HUB/build/med" "$MED"; }
H="$D/mehub-home"
CHAIN=mechain_2401-1
NODE=tcp://127.0.0.1:46657
TX=(--chain-id "$CHAIN" --node "$NODE" --keyring-backend test --gas 400000 --fees 40000umec -y -o json)
med() { HOME="$H" "$MED" "$@"; }
pid() { pgrep -f "$MED start --home $H/.mechain" || true; }
case "${1:-}" in
  init)
    [ -n "$(pid)" ] && kill "$(pid)" && sleep 1
    rm -rf "$H" && mkdir -p "$H"
    ( cd "$HUB" && HOME="$H" PATH="$D/.bin:$PATH" CHAIN_ID=$CHAIN \
        SETTLEMENT_ADDR=127.0.0.1:46657 P2P_ADDRESS=127.0.0.1:46656 GRPC_ADDRESS=127.0.0.1:49090 \
        GRPC_WEB_ADDRESS=127.0.0.1:49091 API_ADDRESS=127.0.0.1:41317 JSONRPC_ADDRESS=127.0.0.1:48545 \
        JSONRPC_WS_ADDRESS=127.0.0.1:48546 sh scripts/setup_local.sh ) > "$D/runs/mehub-setup.log" 2>&1
    C="$H/.mechain/config/config.toml"; A="$H/.mechain/config/app.toml"; G="$H/.mechain/config/genesis.json"
    sed -e 's#^proxy_app = .*#proxy_app = "tcp://127.0.0.1:46658"#' -e 's#^pprof_laddr = .*#pprof_laddr = "127.0.0.1:46060"#' \
        -e 's/^timeout_commit = .*/timeout_commit = "1s"/' "$C" > "$C.tmp" && mv "$C.tmp" "$C"
    sed -e 's#^address = ":8080"#address = "127.0.0.1:46080"#' -e 's#^metrics-address = .*#metrics-address = "127.0.0.1:46065"#' "$A" > "$A.tmp" && mv "$A.tmp" "$A"
    # ME IDs: x/did InitGenesis registers address -> DID exactly like a KYC approval (single-region devnets
    # can't run `kyc approve`; see Leash ID devnet/README.md).
    jq --slurpfile ids "$2" '.app_state.did.infos += [$ids[0][] | {did, address, pubkey: ({"@type":"/cosmos.crypto.secp256k1.PubKey", key: .pubkey} | tostring), status:"DID_STATUS_ACTIVE", regionId:"", kycLevel, sub_account:""}]
       | .app_state.feemarket.params.no_base_fee = true | .app_state.feemarket.params.base_fee = "0"' "$G" > "$G.tmp" && mv "$G.tmp" "$G"
    med validate-genesis > /dev/null && echo "init ok ($CHAIN, rpc $NODE)" ;;
  start)
    [ -n "$(pid)" ] && { echo "already running"; exit 0; }
    nohup env HOME="$H" "$MED" start --home "$H/.mechain" > "$D/runs/mehub-node.log" 2>&1 &
    for _ in $(seq 1 60); do h=$(curl -sf http://127.0.0.1:46657/status | jq -r .result.sync_info.latest_block_height 2>/dev/null || echo 0); [ "${h:-0}" -ge 2 ] && { echo "started (height $h)"; exit 0; }; sleep 1; done
    echo "node did not start; see runs/mehub-node.log"; exit 1 ;;
  stop) p=$(pid); [ -n "$p" ] && kill $p; echo stopped ;;
  fund)
    h=$(med tx bank send user "$2" "${3}umec" "${TX[@]}" | jq -r .txhash)
    for _ in $(seq 1 30); do out=$(med q tx "$h" --node "$NODE" -o json 2>/dev/null) && { echo "fund $2 code=$(echo "$out" | jq -r .code)"; exit 0; }; sleep 1; done
    echo "fund tx $h not found"; exit 1 ;;
  *) sed -n 2,8p "$0"; exit 2 ;;
esac
