use bip39::Mnemonic;
use serde_json::Value;
use std::ops::Add;
use core::time::Duration;
use std::time::SystemTime;
use std::convert::TryInto;
use tendermint_rpc::{request::RequestMessage, endpoint::broadcast::tx_async::Request};
use bytes::BytesMut;
use serde::{Serialize, Deserialize};
use hex::FromHex;
//Ethereum
use ethers::{abi::{Token, ParamType, Error}, core::types::TransactionRequest, types::{transaction::eip2718::TypedTransaction, U256, Address}};
use ethers_signers::{MnemonicBuilder, coins_bip39::English, LocalWallet};
//Cosmos
use cosmrs::{cosmwasm::{MsgStoreCode, MsgInstantiateContract, MsgExecuteContract}, bank::MsgSend, tx::{self, Fee, Msg, SignDoc, SignerInfo, MessageExt}, AccountId, Coin, crypto::secp256k1::SigningKey};
use cosmrs::proto::prost::Message;
use cosmrs::proto::ibc::applications::transfer::v1::MsgTransfer as MT;
use cosmrs::proto::traits::TypeUrl;
use ibc_proto::ibc::applications::transfer::v1::MsgTransfer;

pub fn cosmos_send(
  account_number: u64,
  sequence_number: u64,
  gas: u64, //100_000_000_000u64;
  timeout_height: u32, //9001u32; or u32::MAX
  memo: &str, //"example memo"
  signing_key: &SigningKey,
  signing_address_prefix: &str,
  to_address: &str,
  amount: &str,
  denom: &str,
  chain_id: &str
) -> Result<BytesMut, Error> {
  let public_key = signing_key.public_key();
  let from_address = public_key.account_id(signing_address_prefix).unwrap();
  let to_address = to_address.parse::<AccountId>().unwrap();

  let amount = Coin {
    amount: amount.parse().unwrap(),
    denom: denom.parse().unwrap(),
  };

  let tx_body = tx::Body::new(vec![
    MsgSend {
      from_address,
      to_address,
      amount: vec![amount.clone()],
    }.to_any().unwrap()
  ], memo, timeout_height);

  let auth_info = SignerInfo::single_direct(Some(public_key), sequence_number).auth_info(Fee::from_amount_and_gas(amount, gas));
  let sign_doc = SignDoc::new(&tx_body, &auth_info, &chain_id.parse().unwrap(), account_number).unwrap();  
  // eprintln!("{sign_doc:?}");

  cosmj(sign_doc.sign(&signing_key).unwrap().to_bytes().unwrap())
}

pub fn cosmos_transfer(
  account_number: u64,
  sequence_number: u64,
  gas: u64,
  timeout_height: u32,
  memo: &str,
  signing_key: &SigningKey,
  signing_address_prefix: &str,
  to_address: &str,
  amount: &str,
  denom: &str,
  chain_id: &str,
  source_channel: &str,
  source_port: &str
) -> Result<BytesMut, Error> {
  let public_key = signing_key.public_key();
  let from_address = public_key.account_id(&signing_address_prefix).unwrap();
  let timeout_timestamp: u64 = SystemTime::now()
    .duration_since(SystemTime::UNIX_EPOCH)
    .unwrap()
    .add(Duration::from_secs(600)).as_nanos().try_into().unwrap();

  let coin = Coin {
    amount: amount.parse().unwrap(),
    denom: denom.parse().unwrap(),
  };
  let amount = amount.to_string();
  let denom = denom.to_string();

  let tx_body = tx::Body::new(vec![
    cosmrs::Any {
      type_url: MT::TYPE_URL.to_string(),
      value: MsgTransfer {
        sender: from_address.into(),
        receiver: to_address.to_string(),
        token: Some(ibc_proto::cosmos::base::v1beta1::Coin{amount, denom}),
        timeout_height: None,
        source_channel: source_channel.to_string(),
        source_port: source_port.to_string(),
        timeout_timestamp,
        memo: "".to_string(), //TODO handle internal memo
      }.encode_to_vec()
    }
  ], memo, timeout_height);

  let auth_info = SignerInfo::single_direct(Some(public_key), sequence_number).auth_info(Fee::from_amount_and_gas(coin, gas));
  let sign_doc = SignDoc::new(&tx_body, &auth_info, &chain_id.parse().unwrap(), account_number).unwrap();

  cosmj(sign_doc.sign(&signing_key).unwrap().to_bytes().unwrap())
}


pub fn cosmos_deploy_wasm(
  account_number: u64,
  sequence_number: u64,
  gas: u64,
  timeout_height: u32,
  memo: &str,
  signing_key: &SigningKey,
  signing_address_prefix: &str,
  amount: &str,
  denom: &str,
  chain_id: &str,
  wasm_path: &str,
) -> Result<BytesMut, Error> {
  let public_key = signing_key.public_key();
  let from_address = public_key.account_id(&signing_address_prefix).unwrap();

  let amount = Coin {
    amount: amount.parse().unwrap(),
    denom: denom.parse().unwrap(),
  };

  let wasm_byte_code = std::fs::read(wasm_path).unwrap();
  let tx_body = tx::Body::new(vec![
    MsgStoreCode {
      instantiate_permission: None,
      sender: from_address,
      wasm_byte_code,
    }.to_any().unwrap()
  ], memo, timeout_height);

  let auth_info = SignerInfo::single_direct(Some(public_key), sequence_number).auth_info(Fee::from_amount_and_gas(amount, gas));
  let sign_doc = SignDoc::new(&tx_body, &auth_info, &chain_id.parse().unwrap(), account_number).unwrap();

  cosmj(sign_doc.sign(&signing_key).unwrap().to_bytes().unwrap())
}

pub fn cosmos_instantiate_wasm(
  account_number: u64,
  sequence_number: u64,
  gas: u64,
  timeout_height: u32,
  memo: &str,
  signing_key: &SigningKey,
  signing_address_prefix: &str,
  amount: &str,
  denom: &str,
  chain_id: &str,
  code_id: u64,
  label: &str,
  msg: &str
) -> Result<BytesMut, Error> {
  let public_key = signing_key.public_key();
  let sender = public_key.account_id(&signing_address_prefix).unwrap();

  let amount = Coin {
    amount: amount.parse().unwrap(),
    denom: denom.parse().unwrap(),
  };

  let tx_body = tx::Body::new(vec![
    MsgInstantiateContract {
      admin: None,
      code_id,
      sender,
      label: Some(label.to_string()),
      funds: vec![amount.clone()],
      msg: msg.to_string().to_bytes().unwrap()
    }.to_any().unwrap()
  ], memo, timeout_height);

  let auth_info = SignerInfo::single_direct(Some(public_key), sequence_number).auth_info(Fee::from_amount_and_gas(amount, gas));
  let sign_doc = SignDoc::new(&tx_body, &auth_info, &chain_id.parse().unwrap(), account_number).unwrap();

  cosmj(sign_doc.sign(&signing_key).unwrap().to_bytes().unwrap())
}

pub fn cosmos_wasm_execute(
  account_number: u64,
  sequence_number: u64,
  gas: u64,
  timeout_height: u32,
  memo: &str,
  signing_key: &SigningKey,
  signing_address_prefix: &str,
  amount: &str,
  denom: &str,
  chain_id: &str,
  contract: &str,
  msg: &str
) -> Result<BytesMut, Error> {
  let public_key = signing_key.public_key();
  let sender = public_key.account_id(&signing_address_prefix).unwrap();

  let amount = Coin {
    amount: amount.parse().unwrap(),
    denom: denom.parse().unwrap(),
  };

  let tx_body = tx::Body::new(vec![
    MsgExecuteContract{
      contract: contract.parse::<AccountId>().unwrap(),
      sender,
      funds: vec![amount.clone()],
      msg: msg.to_string().to_bytes().unwrap()
    }.to_any().unwrap()
  ], memo, timeout_height);

  let auth_info = SignerInfo::single_direct(Some(public_key), sequence_number).auth_info(Fee::from_amount_and_gas(amount, gas));
  let sign_doc = SignDoc::new(&tx_body, &auth_info, &chain_id.parse().unwrap(), account_number).unwrap();

  cosmj(sign_doc.sign(&signing_key).unwrap().to_bytes().unwrap())
}


#[derive(Debug, PartialEq, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Bytecode {
  object: String,
  opcodes: String,
  source_map: String,
}

#[derive(Debug, PartialEq, Clone, Deserialize)]
pub struct SC {
  bytecode: Bytecode,
  abi: ethers::core::abi::Abi
}

#[derive(Debug, PartialEq, Clone, Deserialize)]
pub struct EvmQueryBalanceResponse {
  pub id: u64,
  pub result: String,
}

pub fn evm_query_balance(address: &str, next_id: u64) -> Result<BytesMut, Error> {
  evmj(next_id, "eth_getBalance", [address, "finalized"])
}

pub fn evm_query_block(next_id: u64) -> Result<BytesMut, Error> {
  evmj(next_id, "eth_getBlockByNumber", ["finalized"])
}

fn evmj<T: Serialize>(id: u64, method: &str, params: T) -> Result<BytesMut, Error> {
  Ok(BytesMut::from(serde_json::to_string(&EvmRequest::new(id, method, params))? .as_bytes()))
}

fn cosmj(tx: Vec<u8>) -> Result<BytesMut, Error> {
  Ok(BytesMut::from(Request::new(tx).into_json().as_bytes()))
}

pub type EvmWallet = ethers_signers::Wallet<ecdsa::SigningKey<k256::Secp256k1>>;
pub type Abi = ethers::core::abi::Abi;

pub fn evm_random_wallet() -> EvmWallet {
  LocalWallet::new(&mut rand::thread_rng())
}

pub fn evm_phrase_wallet(phrase : &str) -> EvmWallet {
  MnemonicBuilder::<English>::default()
  .phrase(phrase)
  .build().unwrap()
}

pub fn evm_sk_wallet(signing_key : &str) -> EvmWallet {
  signing_key.parse().unwrap()
}

pub fn cosmos_phrase_wallet(phrase : &str) -> SigningKey {
  SigningKey::derive_from_path(
    bip39::Seed::new(&Mnemonic::from_phrase(phrase, bip39::Language::English).unwrap(),""), 
    &"m/44'/118'/0'/0/0".parse().unwrap()
  ).unwrap()
}

pub fn cosmos_sk_wallet(secret_key : &str) -> SigningKey {
  let sk = <Vec<u8>>::from_hex(secret_key).unwrap();
  cosmrs::crypto::secp256k1::SigningKey::from_slice(sk.as_slice()).unwrap()
}

pub fn evm_abi(path: &str) -> Abi{
  let json = std::fs::read_to_string(path).unwrap();
  serde_json::from_str::<SC>(json.as_str()).unwrap().abi
}


pub fn evm_send(
  wallet: &EvmWallet,
  gas: &str,
  gas_price: &str,
  nonce: u64,
  to_address: &str,
  amount: &str,
  chain_id: u64,
  next_id: u64,
) -> Result<BytesMut, Error> {

  let tx = TransactionRequest::new()
   .chain_id(chain_id)
   .to(to_address)
   .gas(gas.as_bytes())
   .gas_price(gas_price.as_bytes())
   .nonce(nonce)
   .value(amount.as_bytes());
  
  let tx2: TypedTransaction = tx.into();
  let tx3 = tx2.rlp_signed(&wallet.sign_transaction_sync(&tx2).unwrap());
  let rlp = ethers::utils::serialize(&tx3);

  evmj(next_id, "eth_sendRawTransaction", [rlp])
}

pub fn evm_deploy_and_instantiate_contract(
  msg: &str, // {"function_name": {"name_arg1": arg1, "name_arg2": arg2, ..}}
  wallet: &EvmWallet,
  path: &str,
  gas: &str,
  gas_price: &str,
  nonce: u64,
  chain_id: u64,
  next_id: u64,
) -> Result<BytesMut, Error> {
  let json = std::fs::read_to_string(path).unwrap();
  let sc = serde_json::from_str::<SC>(json.as_str()).unwrap();
  let data = (sc.bytecode.object.to_string() + &hex::ToHex::encode_hex::<String>(&constructor_to_data(msg, &sc.abi)?)).as_bytes().to_vec();

  let tx = TransactionRequest::new().data(data)
    .chain_id(chain_id)
    // .to(wallet.address())
    .gas(gas.as_bytes())
    .gas_price(gas_price.as_bytes())
    .nonce(nonce);
    // .value(0);

  let tx2: TypedTransaction = tx.into();

  let tx3 = tx2.rlp_signed(&wallet.sign_transaction_sync(&tx2).unwrap());
  let rlp = ethers::utils::serialize(&tx3);

  evmj(next_id,"eth_sendRawTransaction", [rlp])
}

macro_rules! e {
    ( $( $x:expr ),* ) => {
        {
            $(
                Error::Other($x.into())
            )*
        }
    };
}

pub fn evm_execute(
  msg: &str, // {"function_name": {"name_arg1": arg1, "name_arg2": arg2, ..}}
  wallet: &EvmWallet,
  abi: &Abi,
  address: &str,
  amount: &str,
  gas: &str,
  gas_price: &str,
  nonce: u64,
  chain_id: u64,
  next_id: u64,
) -> Result<BytesMut, Error> {

  let tx :TypedTransaction = TransactionRequest::new().data(function_to_data(msg, abi)?)
    .chain_id(chain_id)
    .to(address)
    .gas(gas.as_bytes())
    .gas_price(gas_price.as_bytes())
    .nonce(nonce)
    .value(amount.as_bytes()).into();

  let rlp = ethers::utils::serialize(&tx.rlp_signed(&wallet.sign_transaction_sync(&tx).or_else(|e| Err(e!(e.to_string())))? ));

  evmj(next_id,"eth_sendRawTransaction", [rlp])
}

fn function_to_data(msg: &str, abi: &Abi) -> Result<ethers::abi::Bytes, Error> {
  serde_json::from_str::<Value>(msg)?
      .as_object().ok_or(e!(format!("{msg} as object"))).and_then(|o|
      (o.len() == 1).then(|| o).ok_or(e!(format!("{msg} as 1 entry object"))).and_then(|o|
          Ok(o.iter().next().unwrap())).and_then(|(name, v)|
          abi.function(name).and_then(|fun| function_v_to_data(v,fun))
      )
  )
}

fn constructor_to_data(msg: &str, abi: &Abi) -> Result<ethers::abi::Bytes, Error> {
  abi.constructor().ok_or(e!(format!("could not get constructor"))).and_then(|fun| constructor_v_to_data(&serde_json::from_str::<Value>(msg)?, fun))
}

fn function_v_to_data(v: &Value, fun: &ethers::abi::Function) -> Result<ethers::abi::Bytes, Error> {
  v.as_array().ok_or(e!(format!("{v} value as array"))).and_then(|args|
    (fun.inputs.len() == args.len()).then(|| (fun,args.iter().collect::<Vec<&Value>>())).ok_or(e!(format!("{v} inputs.len != args.len"))).and_then(args_to_data)
  )
  .or_else(|_|
  v.as_object().ok_or(e!(format!("{v} value as object"))).and_then(| args|
    (fun.inputs.len() == args.len()).then(|| (fun, args.into_iter().map(|(_,s)|s).collect::<Vec<&Value>>())).ok_or(e!(format!("{v} inputs.len != args.len"))).and_then(args_to_data)
  ))
}

fn constructor_v_to_data(v: &Value, fun: &ethers::abi::Constructor) -> Result<ethers::abi::Bytes, Error> {
  v.as_array().ok_or(e!(format!("{v} value as array"))).and_then(|args|
    (fun.inputs.len() == args.len()).then(|| (fun,args.iter().collect::<Vec<&Value>>())).ok_or(e!(format!("{v} inputs.len != args.len"))).and_then(constructor_args_to_data)
  )
  .or_else(|_|
  v.as_object().ok_or(e!(format!("{v} value as object"))).and_then(| args|
    (fun.inputs.len() == args.len()).then(|| (fun, args.into_iter().map(|(_,s)|s).collect::<Vec<&Value>>())).ok_or(e!(format!("{v} inputs.len != args.len"))).and_then(constructor_args_to_data)
  ))
}

fn args_to_data((fun, args): (&ethers::abi::Function, Vec<&Value>)) -> Result<ethers::abi::Bytes, Error> {
  fun.inputs.iter().zip(&args).try_fold(Vec::with_capacity(args.len()), |mut acc, (p, v)|
    to_token(v, &p.kind).and_then(|token| { acc.push(token); Ok(acc) })
  ).and_then(|df| fun.encode_input(df.as_slice()))
}

fn constructor_args_to_data((fun, args): (&ethers::abi::Constructor, Vec<&Value>)) -> Result<ethers::abi::Bytes, Error> {
  fun.inputs.iter().zip(&args).try_fold(Vec::with_capacity(args.len()), |mut acc, (p, v)|
    to_token(v, &p.kind).and_then(|token| { acc.push(token); Ok(acc) })
  ).and_then(|df| fun.encode_input(Vec::new(), df.as_slice()))
}

fn to_token(v: &Value , pt: &ParamType) -> Result<Token, Error> { match pt {
  ParamType::Bool => v.as_bool().ok_or(e!(format!("{v} as bool"))).and_then(|b|
    Ok(Token::Bool(b))),
  ParamType::Array(pt) => v.as_array().ok_or(e!(format!("{v} as {pt}"))).and_then(|a|
    Ok(Token::Array(a.iter().map_while(|v| to_token(v, pt).ok()).collect::<Vec<Token>>()))),
  ParamType::FixedArray(pt, l) => v.as_array().and_then(|a| {
    let st =a.iter().map_while(|v| to_token(v, pt).ok()).collect::<Vec<Token>>();
    if st.len() == *l { Some(Token::FixedArray(st)) } else { None }
  }).ok_or(Error::Other(format!("Error while expanding fixed_array {l} of {pt}").into())),
  ParamType::Address => v.as_str().ok_or(e!("")).and_then(|s|
    s.parse::<Address>().and_then(|a| Ok(Token::Address(a))).or_else(|e| Err(e!(e.to_string())))),
  ParamType::Bytes => v.as_str().ok_or(e!("")).and_then(|s|
    <Vec<u8>>::from_hex(s).and_then(|b| Ok(Token::Bytes(b))).or_else(|e| Err(e!(e.to_string())))),
  ParamType::FixedBytes(l) => v.as_str().and_then(|s|
    <Vec<u8>>::from_hex(s).and_then(|b| if b.len() == *l { Ok(Token::FixedBytes(b)) } else { Err(hex::FromHexError::OddLength) }).ok()
  ).ok_or(Error::Other("".into())),
  ParamType::String =>  v.as_str().and_then(|s| 
    Some(Token::String(s.to_owned()))
  ).ok_or(Error::Other("".into())),
  ParamType::Uint(_) => v.as_str().and_then(|s| 
    U256::from_dec_str(s).and_then(|u| Ok(Token::Uint(u))).ok()
  ).ok_or(Error::Other("".into())),
  ParamType::Int(_) => v.as_str().and_then(|s| 
    U256::from_dec_str(s).and_then(|u| Ok(Token::Int(u))).ok()
  ).ok_or(Error::Other("".into())),
  ParamType::Tuple(pts) => v.as_array().and_then(|a|
    if pts.len() == a.len() {
      Some(Token::Tuple(a.iter().zip(pts).map_while(|(v, pt)| to_token(v, pt).ok()).collect::<Vec<Token>>()))
    } else { None }
  ).ok_or(Error::Other("".into()))
}}


pub fn to_value(token : &Token) -> Value {
  match token {
    Token::Tuple(sts) | Token::Array(sts) | Token::FixedArray(sts) =>
      Value::Array(sts.iter().map(|st| to_value(st)).collect::<Vec<Value>>()),
    Token::Bool(b) => Value::Bool(*b),
    Token::Address(a) => Value::String(format!("0x{a:x}")),
    Token::Uint(i) | Token::Int(i) => Value::String(format!("{i}")),
    Token::Bytes(b) | Token::FixedBytes(b)=> Value::String(hex::encode(b)),
    Token::String(s) => Value::String(s.into()),
  }
}

use std::ffi::{CString,CStr};
use std::os::raw::c_char;
// CString -> IO CString
// path <- newCString "path"
// phrase <- newCString "phrase"
// path phrase (fromIntegral 1) >>= peekCString >>= return
#[no_mangle]
pub extern "C" fn protoss_evm_deploy_and_instantiate_contract(
  path: *const c_char,
  phrase: *const c_char,
  msg: *const c_char,
  nonce: u64,
  next_id: u64,
  chain_id: u64
) -> *const c_char {
  let path = unsafe { CStr::from_ptr(path).to_string_lossy().into_owned() };
  let phrase = unsafe { CStr::from_ptr(phrase).to_string_lossy().into_owned() };
  let msg = unsafe { CStr::from_ptr(msg).to_string_lossy().into_owned() };
  eprintln!("received {} {} {}", path, phrase, nonce);

  let gas = "521975";
  let gas_price = "20000000000";

  let buf = evm_deploy_and_instantiate_contract(msg.as_str(), &evm_phrase_wallet(phrase.as_str()), path.as_str(), gas, gas_price, nonce, chain_id, next_id).unwrap();
  CString::new(buf).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn protoss_cosmos_send_phrase(
  phrase: *const c_char,
  nonce: u64,
  addr_prefix: *const c_char,
  to_address: *const c_char,
  amount: *const c_char,
  denom: *const c_char,
  // next_id: u64,
  chain_id: *const c_char
) -> *const c_char {
  let phrase = unsafe { CStr::from_ptr(phrase).to_string_lossy().into_owned() };
  let addr_prefix = unsafe { CStr::from_ptr(addr_prefix).to_string_lossy().into_owned() };
  let to_address = unsafe { CStr::from_ptr(to_address).to_string_lossy().into_owned() };
  let amount = unsafe { CStr::from_ptr(amount).to_string_lossy().into_owned() };
  let denom = unsafe { CStr::from_ptr(denom).to_string_lossy().into_owned() };
  let chain_id = unsafe { CStr::from_ptr(chain_id).to_string_lossy().into_owned() };

  let gas =  100_000_000_000u64;
  let memo = "nomemo";
  let timeout_height = u32::MAX;

  let signing_key = cosmos_phrase_wallet(phrase.as_str());

  let buf = cosmos_send(0,nonce, gas, timeout_height, memo,
    &signing_key, addr_prefix.as_str(),to_address.as_str(), amount.as_str(), denom.as_str(), chain_id.as_str()).unwrap();
  CString::new(buf).unwrap().into_raw()
}


#[no_mangle]
pub extern "C" fn protoss_cosmos_transfer_phrase(
  phrase: *const c_char,
  nonce: u64,
  addr_prefix: *const c_char,
  to_address: *const c_char,
  amount: *const c_char,
  denom: *const c_char,
  // next_id: u64,
  chain_id: u64,
  source_channel: *const c_char,
  source_port: *const c_char
) -> *const c_char {
  let phrase = unsafe { CStr::from_ptr(phrase).to_string_lossy().into_owned() };
  let addr_prefix = unsafe { CStr::from_ptr(addr_prefix).to_string_lossy().into_owned() };
  let to_address = unsafe { CStr::from_ptr(to_address).to_string_lossy().into_owned() };
  let amount = unsafe { CStr::from_ptr(amount).to_string_lossy().into_owned() };
  let denom = unsafe { CStr::from_ptr(denom).to_string_lossy().into_owned() };
  let source_channel = unsafe { CStr::from_ptr(source_channel).to_str().unwrap().to_string() };
  let source_port = unsafe { CStr::from_ptr(source_port).to_str().unwrap().to_string() };
  eprintln!("received {} {}", phrase, nonce);

  let gas =  100_000_000_000u64;
  let memo = "nomemo";
  let timeout_height = u32::MAX;

  let signing_key = cosmos_phrase_wallet(phrase.as_str());

  let buf = cosmos_transfer(0,nonce, gas, timeout_height, memo,
    &signing_key, addr_prefix.as_str(),to_address.as_str(), 
    amount.as_str(), denom.as_str(), format!("{chain_id}").as_str(),
    source_channel.as_str(), source_port.as_str()
  ).unwrap();
  CString::new(buf).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn protoss_cosmos_new_sk() -> *const c_char{
  let sk =format!("{:x}", k256::ecdsa::SigningKey::random(&mut rand_core::OsRng).to_bytes());
  CString::new(sk.as_bytes()).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn protoss_cosmos_sk_address(sk: *const c_char, addr_prefix: *const c_char) -> *const c_char {
  let sk = unsafe { CStr::from_ptr(sk).to_string_lossy().into_owned() };
  let addr_prefix = unsafe { CStr::from_ptr(addr_prefix).to_string_lossy().into_owned() };

  let public_key: cosmrs::crypto::PublicKey = cosmos_sk_wallet(sk.as_str()).public_key();
  let address = public_key.account_id(addr_prefix.as_str()).unwrap().to_string();
  CString::new(address.as_bytes()).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn protoss_cosmos_phrase_address(phrase: *const c_char, addr_prefix: *const c_char) -> *const c_char {
  let phrase = unsafe { CStr::from_ptr(phrase).to_string_lossy().into_owned() };
  let addr_prefix = unsafe { CStr::from_ptr(addr_prefix).to_string_lossy().into_owned() };

  let public_key: cosmrs::crypto::PublicKey = cosmos_phrase_wallet(phrase.as_str()).public_key();
  let address = public_key.account_id(addr_prefix.as_str()).unwrap().to_string();
  CString::new(address.as_bytes()).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn protoss_cosmos_tx(
  // phrase: *const c_char,
  sk: *const c_char,
  account_number: u64, nonce: u64,
  fee_amount: *const c_char, fee_denom: *const c_char, gas: u64,
  body_bytes: *const c_char,
  chain_id: *const c_char
) -> *const c_char{
  // let phrase = unsafe { CStr::from_ptr(phrase).to_string_lossy().into_owned() };
  let sk = unsafe { CStr::from_ptr(sk).to_string_lossy().into_owned() };
  let fee_amount = unsafe { CStr::from_ptr(fee_amount).to_string_lossy().into_owned() };
  let fee_denom = unsafe { CStr::from_ptr(fee_denom).to_string_lossy().into_owned() };
  let body_bytes = unsafe { CStr::from_ptr(body_bytes) };
  let chain_id = unsafe { CStr::from_ptr(chain_id).to_string_lossy().into_owned() };
  
  let amount = Coin {
    amount: fee_amount.parse().unwrap(),
    denom: fee_denom.parse().unwrap(),
  };
  let sequence_number = nonce;
  let signing_key = cosmos_sk_wallet(sk.as_str());
  let auth_info = SignerInfo::single_direct(Some(signing_key.public_key()), sequence_number).auth_info(Fee::from_amount_and_gas(amount, gas));


  let sign_doc = SignDoc{
    body_bytes: body_bytes.to_bytes().to_vec(),
    auth_info_bytes:  auth_info.into_bytes().unwrap(),
    account_number,
    chain_id
  };
  // eprintln!("{sign_doc:?}");
  
  let buf = cosmj(sign_doc.sign(&signing_key).unwrap().to_bytes().unwrap()).unwrap();
  CString::new(buf).unwrap().into_raw()
}


#[no_mangle]
pub extern "C" fn protoss_cosmos_ptx(
  phrase: *const c_char,
  account_number: u64, nonce: u64,
  fee_amount: *const c_char, fee_denom: *const c_char, gas: u64,
  body_bytes: *const c_char,
  chain_id: *const c_char
) -> *const c_char{
  let phrase = unsafe { CStr::from_ptr(phrase).to_string_lossy().into_owned() };
  let fee_amount = unsafe { CStr::from_ptr(fee_amount).to_string_lossy().into_owned() };
  let fee_denom = unsafe { CStr::from_ptr(fee_denom).to_string_lossy().into_owned() };
  let body_bytes = unsafe { CStr::from_ptr(body_bytes) };
  let chain_id = unsafe { CStr::from_ptr(chain_id).to_string_lossy().into_owned() };
  
  let amount = Coin {
    amount: fee_amount.parse().unwrap(),
    denom: fee_denom.parse().unwrap(),
  };
  let sequence_number = nonce;
  let signing_key = cosmos_phrase_wallet(phrase.as_str());
  let auth_info = SignerInfo::single_direct(Some(signing_key.public_key()), sequence_number).auth_info(Fee::from_amount_and_gas(amount, gas));


  let sign_doc = SignDoc{
    body_bytes: body_bytes.to_bytes().to_vec(),
    auth_info_bytes:  auth_info.into_bytes().unwrap(),
    account_number,
    chain_id
  };
  // eprintln!("{sign_doc:?}");
  
  let buf = cosmj(sign_doc.sign(&signing_key).unwrap().to_bytes().unwrap()).unwrap();
  CString::new(buf).unwrap().into_raw()
}

#[derive(Serialize, Deserialize, Debug)]
/// A JSON-RPC request
pub struct EvmRequest<'a, T> {
    id: u64,
    jsonrpc: &'a str,
    method: &'a str,
    #[serde(skip_serializing_if = "is_zst")]
    params: T,
}

impl<'a, T> EvmRequest<'a, T> {
  /// Creates a new JSON RPC request
  pub fn new(id: u64, method: &'a str, params: T) -> Self {
      Self { id, jsonrpc: "2.0", method, params }
  }
}

fn is_zst<T>(_t: &T) -> bool {
  std::mem::size_of::<T>() == 0
}

#[no_mangle]
pub extern "C" fn protoss_uuid4() -> *const c_char {
  CString::new(uuid::Uuid::new_v4().as_bytes()).unwrap().into_raw()
}

// #[no_mangle]
// pub extern "C" fn cosmos_get_account_info(
//   address: *const c_char,
//   url: *const c_char //format!("http://{}:9092", host)
// ) -> *const u8 {
//   let url = unsafe { CStr::from_ptr(url).to_str().unwrap().to_string() };
//   let address = unsafe { CStr::from_ptr(address).to_str().unwrap().to_string() };
  
//   let rt = Runtime::new().unwrap();

//   let rpc_address = Uri::try_from(url).unwrap();
//   let account: BaseAccount = rt.block_on(async {
//     let mut query = cosmos_sdk_proto::cosmos::auth::v1beta1::query_client::QueryClient::connect(rpc_address).await.unwrap();
//     let response = query.account(QueryAccountRequest{address}).await.unwrap();
//     return BaseAccount::decode(response.get_ref().account.as_ref().unwrap().value.as_slice()).unwrap();
//   });
//   let mut buf = BytesMut::with_capacity(16);
//   buf.put_u64(account.account_number);
//   buf.put_u64(account.sequence);
//   return buf[..].as_ptr();
// }



