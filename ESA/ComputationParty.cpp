// (C) 2018 University of NKU. Free for used

/*
 * ComputationParty.cpp
 *
 */
#include "ESA/ComputationParty.h"


#include "Tools/ezOptionParser.h"
#include "Exceptions/Exceptions.h"
#include "Networking/data.h"
#include "Tools/octetStream.h"

#include <vector>
#include <string>
#include <fstream>
#include <math.h> 

typedef struct CP_thread_bucket_elgamal {
   CP* obj;
   vector<ElGamalCiphertext>* sh_CHS;
   vector<BIGNUM*>* sh_HS;
   int t_id;
    int _start;
   int _internal;
} thread_bucket_elgamal_info;

CP::CP(int argc, const char** argv)
{
    ez::ezOptionParser opt;

    opt.syntax = "./CP.x [OPTIONS]\n";
    opt.example = "./CP.x -np 5 -ndp 1 -p 0 -nt 1 -nB 200000 -uN 20000\n";
    opt.add(
        "5", // Default.
        0, // Required?
        1, // Number of args expected.
        0, // Delimiter if expecting multiple args.
        "number of computation parties (default: 5)", // Help description.
        "-np", // Flag token.
        "--number_parties" // Flag token.
    );
    opt.add(
        "1", // Default.
        0, // Required?
        1, // Number of args expected.
        0, // Delimiter if expecting multiple args.
        "number of data parties (default: 1)", // Help description.
        "-ndp", // Flag token.
        "--number_data_parties" // Flag token.
    );
    opt.add(
        "100", // Default.
        0, // Required?
        1, // Number of args expected.
        0, // Delimiter if expecting multiple args.
        "number of the party (starting from 0)", // Help description.
        "-p", // Flag token.
        "--my_num" // Flag token.
    );
    opt.add(
          "", // Default.
          0, // Required?
          1, // Number of args expected.
          0, // Delimiter if expecting multiple args.
          "Port to listen on (default: port number base + player number)", // Help description.
          "-mp", // Flag token.
          "--my-port" // Flag token.
    );
    opt.add(
          "5000", // Default.
          0, // Required?
          1, // Number of args expected.
          0, // Delimiter if expecting multiple args.
          "Port number base to attempt to start connections from (default: 5000)", // Help description.
          "-pn", // Flag token.
          "--portnumbase" // Flag token.
    );
    opt.add(
          "localhost", // Default.
          0, // Required?
          1, // Number of args expected.
          0, // Delimiter if expecting multiple args.
          "Host where Server.x is running to coordinate startup (default: localhost). Ignored if --ip-file-name is used.", // Help description.
          "-h", // Flag token.
          "--hostname" // Flag token.
    );
    opt.add(
            "1", // Default.
            0, // Required?
            1, // Number of args expected.
            0, // Delimiter if expecting multiple args.
            "number of the threads(default 1)", // Help description.
            "-nt", // Flag token.
            "--number_threads" // Flag token.
    );
    opt.add(
            "20000", // Default.
            0, // Required?
            1, // Number of args expected.
            0, // Delimiter if expecting multiple args.
            "number of bins", // Help description.
            "-uN", // Flag token.
            "--number_buckets" // Flag token.
    );
    opt.add(
            "0.3", // Default.
            0, // Required?
            1, // Number of args expected.
            0, // Delimiter if expecting multiple args.
            "value_of_epsilon", // Help description.
            "-epsilon", // Flag token.
            "--value_of_epsilon" // Flag token.
    );
    opt.add(
            "0.000000000001", // Default.
            0, // Required?
            1, // Number of args expected.
            0, // Delimiter if expecting multiple args.
            "parameter: delta", // Help description.
            "-delta", // Flag token.
            "--value_of_delta" // Flag token.
    );



    opt.parse(argc, argv);

    string usage;
    string hostname;
    opt.get("--number_parties")->getInt(nparties);
    opt.get("--number_data_parties")->getInt(ndparties);
    opt.get("--my_num")->getInt(mynum);
    opt.get("--portnumbase")->getInt(pnbase);
    opt.get("--hostname")->getString(hostname);
    opt.get("--number_buckets")->getInt(n_bins);
    opt.get("--number_threads")->getInt(nthreads);
    opt.get("--value_of_delta")->getDouble(delta);
    opt.get("--value_of_epsilon")->getDouble(epsilon);



    if(mynum>10)
        throw runtime_error("the player number have not been set!");

    ez::OptionGroup* mp_opt = opt.get("--my-port");
    if (mp_opt->isSet)
      mp_opt->getInt(my_port);
    else
      my_port = Names::DEFAULT_PORT;


    
    // ******************************** Network Part ***********************************
    CommsecKeysPackage *keys = NULL;
    vector<Names> playerNames(nthreads*communication_multiplier);

    for(int i=0; i<nthreads*communication_multiplier; i++){
        playerNames[i].init(mynum, pnbase+port_increase*i, my_port, hostname.c_str());
        playerNames[i].set_keys(keys);
    }  

    //p2p whole connected
    thread_player.resize(nthreads*communication_multiplier);
    commu_timer.resize(nparties*nthreads*communication_multiplier);
    for(int i=0; i<nthreads*communication_multiplier; i++){
        thread_player[i] = new Player(playerNames[i], 0);
    }
    player = thread_player[0];
    CP_sockets.resize(nthreads*communication_multiplier);
    for(int i=0; i<nthreads*communication_multiplier; i++){
        CP_sockets[i].resize(nparties);
        for(int k=0; k<nparties; k++){
            CP_sockets[i][k] = thread_player[i]->socket(k);
        }
    }

    //math setup
    sys.resize(nthreads);
    for(int i=0; i<nthreads; i++){
        sys[i] = new ElGamal(nparties, PRINT);
    }

    bn_ctx.resize(nthreads);
    for(int i=0; i<nthreads; i++){
        bn_ctx[i] = BN_CTX_new();
    }
    

    //******************************** Data Collection Phase *****************************
    DP_connector dp_handle;
    dp_handle.init(n_bins, mynum, pnbase, my_port,ndparties, sys[0]->q);
    dp_handle.start(share_HS);



    // multithread 
    mutex_go = PTHREAD_MUTEX_INITIALIZER;
    local_Go.resize(nthreads);
    mutex_local_go.resize(nthreads);
    for(int i=0; i<nthreads; i++){
        mutex_local_go[i] = PTHREAD_MUTEX_INITIALIZER;
    }
    
}

CP::~CP(){
    for(int i=0; i<nthreads; i++){
        delete thread_player[i];
        delete sys[i];
        BN_CTX_free(bn_ctx[i]);
    }

    for(unsigned int i=0; i<share_HS.size(); i++){
        BN_free(share_HS[i]);
    }
}

void CP::_key_gen(int thread_num, bool multi_thread){
    /*
    * broadcast the partial public key and NIZK proof
    */
    vector<octetStream> vec_shares(nparties);
    vector<EC_POINT *> partial_public_keys(nparties);
    for(int i=0; i<nparties; i++){
        partial_public_keys[i] = EC_POINT_new(sys[thread_num]->curve);
    }
    vector<NIZK_DL_Proof*> proof_dl(nparties);
    for(int i=0; i<nparties; i++){
        proof_dl[i] = new NIZK_DL_Proof(sys[thread_num]->curve,sys[thread_num]->q);
    }

    // pack the partial public key
    partial_public_keys[mynum] = sys[thread_num]->partial_public_key;
    pack(sys[thread_num]->curve,partial_public_keys[mynum], vec_shares[mynum]);

    // pack the proof
    sys[thread_num]->NIZK_DL_Prove(*proof_dl[mynum], sys[thread_num]->partial_secret_key, sys[thread_num]->partial_public_key);
    proof_dl[mynum]->pack(vec_shares[mynum]);

    // broadcast
    thread_player[thread_num]->Broadcast_Receive(vec_shares);

    // unpack
    for(int i=0; i<nparties; i++){
        if(i == mynum){
            continue;
        }
        unpack(sys[thread_num]->curve,partial_public_keys[i],vec_shares[i]);
        proof_dl[i]->unpack(vec_shares[i]);
    }

    // // verify
    bool ret = true;
    for(int i=0; i<nparties; i++){
        if(i == mynum){
            continue;
        }
        ret &= sys[thread_num]->NIZK_DL_Verify(*proof_dl[i], partial_public_keys[i]);
    }

    if(!ret){
        throw bad_keygen("\tNIZK_DL_Verify failed");
    }

    // compute the global public key
    for(int i=0; i<nparties; i++){
        if(i == mynum){
            continue;
        }
        sys[thread_num]->add_other_public_key(partial_public_keys[i], i);
    }

    // deconstruct
    for(int i=0; i<nparties; i++){
        delete proof_dl[i];
    }

    if(multi_thread){
        pthread_mutex_lock(&mutex_go); 
        Go++;
        pthread_mutex_unlock(&mutex_go);
    }
}

void* CP::thread_key_gen(void* arg){
    thread_bucket_elgamal_info* data = static_cast<thread_bucket_elgamal_info*>(arg);
    CP* obj = data->obj;
    
    obj->_key_gen(data->t_id,true);

    pthread_exit(NULL);
}

void CP::key_gen(){
    if(thread_player.size() == 0){
        throw runtime_error("The p2p socket has been expired");
    }

    std::vector<thread_bucket_elgamal_info> thread_bucket_elgamal_data(nthreads);
    Go = 0;

    pthread_t* t = new pthread_t[nthreads];
    for(int i=0; i<nthreads; i++){
        thread_bucket_elgamal_data[i].obj = this;
        thread_bucket_elgamal_data[i].t_id = i;
        pthread_create(&t[i], NULL,thread_key_gen, (void*) &thread_bucket_elgamal_data[i]);
    }
    

    while(Go < nthreads){
        usleep(10);
    }

    delete t;
}


void CP::get_encrypted_HS(vector<BIGNUM *>& sh_HS, vector<ElGamalCiphertext>& sh_CHS, int start, int internal, int thread_num, bool multi_thread){
    int end = internal+start>n_bins ? n_bins : internal+start;
    internal = internal+start>n_bins ? n_bins-start : internal;
    

    vector<ElGamalCiphertext> tmp_Ciphers(internal);   
    for(int i=0; i<internal; i++){
        tmp_Ciphers[i].init(sys[thread_num]->curve);
    }

    EC_POINT *tmp_M = EC_POINT_new(sys[thread_num]->curve);
    BIGNUM *tmp_r = BN_new();

    vector<octetStream> vec_shares(nparties);
    NIZK_DL_Proof tmp_proof_dl(sys[thread_num]->curve,sys[thread_num]->q);


    /*
    *   Encode, Encrypt and proof
    */  
    int offset = 0;
    for(int i=start; i<end; i++){
        // encode and encrypt my share
        EC_POINT_mul(sys[thread_num]->curve, tmp_M, NULL, sys[thread_num]->G, sh_HS[i], bn_ctx[thread_num]);
        sys[thread_num]->encrypt(tmp_Ciphers[offset], tmp_M, tmp_r);

        // pack the cipher
        tmp_Ciphers[offset].pack(vec_shares[mynum]);

        // pack the corresponding proof
        sys[thread_num]->NIZK_DL_Prove(tmp_proof_dl, tmp_r, tmp_Ciphers[offset].c1);

        tmp_proof_dl.pack(vec_shares[mynum]);

        // update the ptr
        offset++;
    }

    // broadcast
    thread_player[thread_num]->Broadcast_Receive(vec_shares);

    /*
    *   Verify and compute the encryped hash table
    */
    bool ret = true;
    ElGamalCiphertext tmp_cipher(sys[thread_num]->curve); 
    for(int k=0; k<nparties; k++){
        if(k == mynum){
            continue;
        }
        offset = 0;
        for(int i=start; i<end; i++){
            tmp_cipher.unpack(vec_shares[k]);
            tmp_proof_dl.unpack(vec_shares[k]);
            ret &= sys[thread_num]->NIZK_DL_Verify(tmp_proof_dl, tmp_cipher.c1);
            EC_POINT_add(sys[thread_num]->curve, tmp_Ciphers[offset].c1, tmp_Ciphers[offset].c1, tmp_cipher.c1, bn_ctx[thread_num]);
            EC_POINT_add(sys[thread_num]->curve, tmp_Ciphers[offset].c2, tmp_Ciphers[offset].c2, tmp_cipher.c2, bn_ctx[thread_num]);
            offset ++ ;
        }
    }

    if(!ret){
        throw NIZK_proof_fail();
    }

    // get the encrypted hash table
    offset = 0;
    for(int i=start; i<end; i++){
        sh_CHS[i] = tmp_Ciphers[offset++];
    }

    // deconstruction
    BN_free(tmp_r);
    EC_POINT_free(tmp_M);


    if(multi_thread){
        pthread_mutex_lock(&mutex_go); 
        Go++;
        pthread_mutex_unlock(&mutex_go);
    }
}

void* CP::thread_get_encrypted_HS(void* arg){
    thread_bucket_elgamal_info* data = static_cast<thread_bucket_elgamal_info*>(arg);
    CP* obj = data->obj;

    obj->get_encrypted_HS(*(data->sh_HS),*(data->sh_CHS),data->_start,data->_internal,data->t_id,true);

    pthread_exit(NULL);
}
void CP::multi_thread_get_encrypted_HS(vector<BIGNUM *>& sh_HS, vector<ElGamalCiphertext>& sh_CHS){
    if(thread_player.size() == 0){
        throw runtime_error("The p2p socket has been expired");
    }

    std::vector<thread_bucket_elgamal_info> thread_bucket_elgamal_data(nthreads);
    Go = 0;

    int _start = 0;
    int _internal = ceil(((double)(sh_HS.size()))/nthreads);

    if(sh_HS.size() != sh_CHS.size()){
        throw runtime_error("bad value of vector allocation");
    }

    pthread_t* t = new pthread_t[nthreads];
    for(int i=0; i<nthreads; i++){
        thread_bucket_elgamal_data[i].obj = this;
        thread_bucket_elgamal_data[i].t_id = i;
        thread_bucket_elgamal_data[i]._start = _start;
        _start += _internal;
        thread_bucket_elgamal_data[i]._internal = _internal;
        thread_bucket_elgamal_data[i].sh_CHS = &sh_CHS;
        thread_bucket_elgamal_data[i].sh_HS = &sh_HS;
        pthread_create(&t[i], NULL,thread_get_encrypted_HS, (void*) &thread_bucket_elgamal_data[i]);
    }
    

    while(Go < nthreads){
        usleep(10);
    }

    delete t;
}



void CP::shuffling(vector<ElGamalCiphertext>& sh_CHS, int start, int internal, int thread_num, bool multi_thread){
    int n_bits = sh_CHS.size();
    int end = internal+start>n_bits ? n_bits : internal+start;
    internal = internal+start>n_bits ? n_bits-start : internal;


    /*
    *   initial the batch ciphertext
    */
    vector<BIGNUM *> vec_beta(internal);  
    vector<ElGamalCiphertext> vec_new_ciphertext(internal);
    vector<ElGamalCiphertext> vec_old_ciphertext(internal);

    for(int i=0; i<internal; i++){
        vec_beta[i] = BN_new();
        vec_new_ciphertext[i].init(sys[thread_num]->curve);
        vec_old_ciphertext[i].init(sys[thread_num]->curve);
    }

    int offset = 0;
    for (int i = start; i < end; i++) {
        vec_old_ciphertext[offset] = sh_CHS[i];
        offset ++ ;
    }

    octetStream share_stream;

    /*
    *   run the shuffling protocol
    */
    //for(int k=0; k<nparties; k++){
    int k = 0;
        if(k == mynum){
            // construct the environment
            vector<ZK_Shuffle_Prover_Context*> pctx(nparties);
            for(int i=0; i<nparties; i++){
                if(i == mynum){
                    continue;
                }
                pctx[i] = new ZK_Shuffle_Prover_Context(sys[thread_num]->curve, internal, sys[thread_num]->q);
            }

            // re encrypt; fake permutation
            offset = 0;
            for (int i = start; i < end; i++) {
                sys[thread_num]->re_encrypt(vec_new_ciphertext[offset],vec_old_ciphertext[offset], vec_beta[offset]);
                offset ++ ;
            }

            /*
            * ZK shuffle stage 1
            */
            for(int i=0; i<nparties; i++){
                if(i == mynum){
                    continue;
                }
                // generate the proof
                sys[thread_num]->ZK_Shuffle_Prove_Stage_1(*pctx[i], vec_beta, vec_new_ciphertext, vec_old_ciphertext);
                // pack the proof
                share_stream.reset_write_head();
                pctx[i]->stage_1_proof->pack(share_stream);
                // pack the re-encrypted ciphertext
                for(int j=0; j<internal; j++){
                    vec_new_ciphertext[j].pack(share_stream);
                }
                // send to verifier
                thread_player[thread_num]->send_to(i, share_stream);
            }

            // get the challenge
            vector<ZK_Shuffle_Stage_1_Challenge*> challenge1(nparties);
            for(int i=0; i<nparties; i++){
                if(i == mynum){
                    continue;
                }
                challenge1[i] = new ZK_Shuffle_Stage_1_Challenge(sys[thread_num]->curve, internal, sys[thread_num]->q);
                share_stream.reset_write_head();
                thread_player[thread_num]->receive_player(i, share_stream);
                challenge1[i]->unpack(share_stream);
            }   

            /*
            * ZK shuffle stage 2
            */
            // for each parties generate the proof
            for(int i=0; i<nparties; i++){
                if(i == mynum){
                    continue;
                }
                // generate the proof
                sys[thread_num]->ZK_Shuffle_Prove_Stage_2(*pctx[i], challenge1[i]);
                // pack and send
                share_stream.reset_write_head();
                pctx[i]->stage_2_proof->pack(share_stream);
                thread_player[thread_num]->send_to(i,share_stream);
            }

            /*
            * ZK shuffle stage 3
            */
            // get the challenge
            vector<BIGNUM *> lambda(nparties);
            for(int i=0; i<nparties; i++){
                if(i == mynum){
                    continue;
                }
                lambda[i] = BN_new();
                share_stream.reset_write_head();
                thread_player[thread_num]->receive_player(i, share_stream);
                unpack(lambda[i],share_stream);
            }
            // for each parties generate the proof
            for(int i=0; i<nparties; i++){
                if(i == mynum){
                    continue;
                }
                // generate the proof
                sys[thread_num]->ZK_Shuffle_Prove_Stage_3(*pctx[i], vec_beta, lambda[i]);
                // pack and send
                share_stream.reset_write_head();
                pctx[i]->stage_3_proof->pack(share_stream);
                thread_player[thread_num]->send_to(i,share_stream);
            }

            
            // * ZK shuffle stage 4 - ZK simple K shuffle
            
            // get the challenge
            vector<BIGNUM *> t(nparties);
            for(int i=0; i<nparties; i++){
                if(i == mynum){
                    continue;
                }
                t[i] = BN_new();
                share_stream.reset_write_head();
                thread_player[thread_num]->receive_player(i, share_stream);
                unpack(t[i],share_stream);
            }
            // for each parties generate the proof
            for(int i=0; i<nparties; i++){
                if(i == mynum){
                    continue;
                }
                // generate the proof
                sys[thread_num]->ZK_SS_Prove_Stage_1(*pctx[i], t[i]);
                // pack and send
                share_stream.reset_write_head();
                pctx[i]->ss_stage_1_proof->pack(share_stream);
                thread_player[thread_num]->send_to(i,share_stream);
            }

            /*
            * ZK shuffle stage 5 - ZK simple K shuffle
            */
            // get the challenge
            vector<BIGNUM *> c(nparties);
            for(int i=0; i<nparties; i++){
                if(i == mynum){
                    continue;
                }
                c[i] = BN_new();
                share_stream.reset_write_head();
                thread_player[thread_num]->receive_player(i, share_stream);
                unpack(c[i],share_stream);
            }
            // for each parties generate the proof
            for(int i=0; i<nparties; i++){
                if(i == mynum){
                    continue;
                }
                // generate the proof
                sys[thread_num]->ZK_SS_Prove_Stage_2(*pctx[i], c[i]);
                // pack and send
                share_stream.reset_write_head();
                pctx[i]->ss_stage_2_proof->pack(share_stream);
                thread_player[thread_num]->send_to(i,share_stream);
            }
            
            for(int i=0; i<internal; i++){
                vec_old_ciphertext[i] = vec_new_ciphertext[i];
            }

            // deconstruct the environment
            for(int i=0; i<nparties; i++){
                if(i == mynum){
                    continue;
                }
                delete pctx[i];
                delete challenge1[i];
                BN_free(lambda[i]);
                BN_free(t[i]);
                BN_free(c[i]);
            }

        }else{
            ZK_Shuffle_Verifier_Context vctx(sys[thread_num]->curve, internal, sys[thread_num]->q);
            /*
            * ZK shuffle stage 1
            */
            // receive
            share_stream.reset_write_head();
            thread_player[thread_num]->receive_player(k, share_stream);           
            // unpack
            ZK_Shuffle_Stage_1_Proof proof1(sys[thread_num]->curve, internal, sys[thread_num]->q);
            proof1.unpack(share_stream);
            // unpack the re-encrypted ciphertext
            for(int i=0; i<internal; i++){
                vec_new_ciphertext[i].unpack(share_stream);
            }
            // verify
            sys[thread_num]->ZK_Shuffle_Verify_Stage_1(vctx, &proof1);
            // generate challenge1 and send
            share_stream.reset_write_head();  
            vctx.stage_1_challenge->pack(share_stream);
            thread_player[thread_num]->send_to(k,share_stream);

            /*
            * ZK shuffle stage 2
            */
            // receive
            share_stream.reset_write_head();  
            thread_player[thread_num]->receive_player(k, share_stream);    
            // unpack 
            ZK_Shuffle_Stage_2_Proof proof2(sys[thread_num]->curve, internal, sys[thread_num]->q);
            proof2.unpack(share_stream);
            // verify
            sys[thread_num]->ZK_Shuffle_Verify_Stage_2(vctx, &proof2);
            // generate challenge2 and send
            share_stream.reset_write_head();  
            pack(vctx.lambda, sys[thread_num]->q, share_stream);
            thread_player[thread_num]->send_to(k,share_stream);

            /*
            * ZK shuffle stage 3
            */
            // receive
            share_stream.reset_write_head();  
            thread_player[thread_num]->receive_player(k, share_stream);
            // unpack
            ZK_Shuffle_Stage_3_Proof proof3(sys[thread_num]->curve, internal, sys[thread_num]->q);
            proof3.unpack(share_stream);
            // verify
            sys[thread_num]->ZK_Shuffle_Verify_Stage_3(vctx, &proof3);

            /*
            * ZK shuffle stage 4 - ZK simple K shuffle
            */
            // generate challenge and send
            share_stream.reset_write_head();  
            pack(vctx.t, sys[thread_num]->q,share_stream);
            thread_player[thread_num]->send_to(k,share_stream);
            // receive
            share_stream.reset_write_head();  
            thread_player[thread_num]->receive_player(k, share_stream);
            // unpack
            ZK_SS_Stage_1_Proof proof4(sys[thread_num]->curve, internal, sys[thread_num]->q);
            proof4.unpack(share_stream);
            // verify
            sys[thread_num]->ZK_SS_Verify_Stage_1(vctx, &proof4);

            /*
            * ZK shuffle stage 5 - ZK simple K shuffle
            */
            // generate challenge and send
            share_stream.reset_write_head();  
            pack(vctx.c, sys[thread_num]->q,share_stream);
            thread_player[thread_num]->send_to(k,share_stream);
            // receive
            share_stream.reset_write_head();  
            thread_player[thread_num]->receive_player(k, share_stream);
            // unpack
            ZK_SS_Stage_2_Proof proof5(sys[thread_num]->curve, internal, sys[thread_num]->q);
            proof5.unpack(share_stream);

            /*
            *   Final Verify
            */
            bool ret = true;
            ret &= sys[thread_num]->ZK_SS_Verify_Stage_2(vctx, &proof5);
            ret &= sys[thread_num]->ZK_Shuffle_Verify_Final(vctx, vec_new_ciphertext, vec_old_ciphertext);

            if(!ret){
                throw NIZK_proof_fail();
            }

            for(int i=0; i<internal; i++){
                vec_old_ciphertext[i] = vec_new_ciphertext[i];
            }
        }   
    //}

    // get the shuffled ciphertexts
    offset = 0;
    for (int i = start; i < end; i++) {
        sh_CHS[i] = vec_old_ciphertext[offset];
        offset ++ ;
    }

    // deconstruction
    for(int i=0; i<internal; i++){
        BN_free(vec_beta[i]);
    }

    if(multi_thread){
        cout<<" thread_num "<<thread_num <<" completes";
        pthread_mutex_lock(&mutex_go); 
        Go++;
        pthread_mutex_unlock(&mutex_go);
    }
}

void* CP::thread_shuffling(void* arg){
    thread_bucket_elgamal_info* data = static_cast<thread_bucket_elgamal_info*>(arg);
    CP* obj = data->obj;

    obj->shuffling(*(data->sh_CHS),data->_start,data->_internal,data->t_id,true);

    pthread_exit(NULL);
    
}

void CP::multi_thread_shuffling(vector<ElGamalCiphertext>& sh_CHS){
    if(thread_player.size() == 0){
        throw runtime_error("The p2p socket has been expired");
    }

    std::vector<thread_bucket_elgamal_info> thread_bucket_elgamal_data(nthreads);
    Go = 0;

    int _start = 0;
    int _internal = ceil(((double)(sh_CHS.size()))/nthreads);

    pthread_t* t = new pthread_t[nthreads];
    for(int i=0; i<nthreads; i++){
        thread_bucket_elgamal_data[i].obj = this;
        thread_bucket_elgamal_data[i].t_id = i;
        thread_bucket_elgamal_data[i]._start = _start;
        _start += _internal;
        thread_bucket_elgamal_data[i]._internal = _internal;
        thread_bucket_elgamal_data[i].sh_CHS = &sh_CHS;
        pthread_create(&t[i], NULL,thread_shuffling, (void*) &thread_bucket_elgamal_data[i]);
    }
    

    while(Go < nthreads){
        usleep(10);
    }

    delete t;
}



void CP::decrypt(vector<ElGamalCiphertext>& sh_CHS, int start, int internal, int thread_num, bool multi_thread){
    int n_bits = sh_CHS.size();
    int end = internal+start>n_bits ? n_bits : internal+start;
    internal = internal+start>n_bits ? n_bits-start : internal;

    /*
    *   initial the batch ciphertext
    */
    vector<ElGamalCiphertext> vec_new_ciphertext(internal);
    vector<ElGamalCiphertext> vec_old_ciphertext(internal);

    vector<NIZK_DLE_Proof*> proof_dle(internal);
    for(int i=0; i<internal; i++){
        proof_dle[i] = new NIZK_DLE_Proof(sys[thread_num]->curve, sys[thread_num]->q);
    }

    int offset = 0;
    for (int i = start; i < end; i++) {
        vec_old_ciphertext[offset] = sh_CHS[i];
        vec_new_ciphertext[offset].init(sys[thread_num]->curve);
        offset ++ ;
    }

    octetStream share_stream;
    bool ret = true;

    /*
    *   start the protocol
    */
    for(int k=0; k<nparties; k++){
        if(k == mynum){
            for(int i=0; i<internal; i++){
                // decrypt
                sys[thread_num]->partial_decrypt(vec_new_ciphertext[i], vec_old_ciphertext[i]);
                // generate proof
                sys[thread_num]->NIZK_DLE_Prove(*proof_dle[i],vec_new_ciphertext[i],vec_old_ciphertext[i]);
            }

            // pack and send
            share_stream.reset_write_head();
            for(int i=0; i<internal; i++){
                //pack ciphertext
                vec_new_ciphertext[i].pack(share_stream);
                //pack the proof
                proof_dle[i]->pack(share_stream);
            }

            // broadcast
            thread_player[thread_num]->send_all(share_stream);

            // update
            for(int i=0; i<internal; i++){
                vec_old_ciphertext[i] = vec_new_ciphertext[i];
            }

        }else{
            // receive 
            share_stream.reset_write_head();
            thread_player[thread_num]->receive_player(k, share_stream);
            // unpack and verify
            for(int i=0; i<internal; i++){
                // unpack the ciphertext
                vec_new_ciphertext[i].unpack(share_stream);
                // unpack the proof
                proof_dle[i]->unpack(share_stream);

                // verify
                ret &= sys[thread_num]->NIZK_DLE_Verify(*proof_dle[i], sys[thread_num]->other_public_keys[k], vec_new_ciphertext[i], vec_old_ciphertext[i]);
            }


            //update
            for(int i=0; i<internal; i++){
                vec_old_ciphertext[i] = vec_new_ciphertext[i];
            }
        }
    }

    if(!ret){
        throw NIZK_proof_fail();
    }

    // update
    offset = 0;
    for (int i = start; i < end; i++) {
        sh_CHS[i] = vec_old_ciphertext[offset];
        offset ++ ;
    }


    if(multi_thread){
        pthread_mutex_lock(&mutex_go); 
        Go++;
        pthread_mutex_unlock(&mutex_go);
    }

    // deconstruction
    for(int i=0; i<internal; i++){
        delete proof_dle[i];
    }
}

void* CP::thread_decrypt(void* arg){
    thread_bucket_elgamal_info* data = static_cast<thread_bucket_elgamal_info*>(arg);
    CP* obj = data->obj;

    obj->decrypt(*(data->sh_CHS),data->_start,data->_internal,data->t_id,true);

    pthread_exit(NULL);
}


void CP::multi_thread_decrypt(vector<ElGamalCiphertext>& sh_CHS){
    if(thread_player.size() == 0){
        throw runtime_error("The p2p socket has been expired");
    }

    std::vector<thread_bucket_elgamal_info> thread_bucket_elgamal_data(nthreads);
    Go = 0;

    int _start = 0;
    int _internal = ceil(((double)(sh_CHS.size()))/nthreads);

    pthread_t* t = new pthread_t[nthreads];
    for(int i=0; i<nthreads; i++){
        thread_bucket_elgamal_data[i].obj = this;
        thread_bucket_elgamal_data[i].t_id = i;
        thread_bucket_elgamal_data[i]._start = _start;
        _start += _internal;
        thread_bucket_elgamal_data[i]._internal = _internal;
        thread_bucket_elgamal_data[i].sh_CHS = &sh_CHS;
        pthread_create(&t[i], NULL,thread_decrypt, (void*) &thread_bucket_elgamal_data[i]);
    }
    

    while(Go < nthreads){
        usleep(10);
    }

    delete t;
}

int CP::Output(vector<ElGamalCiphertext>& sh_CHS){
    EC_POINT *M = EC_POINT_new(sys[0]->curve);
    BIGNUM *zero = BN_new();
    EC_POINT_mul(sys[0]->curve, M, NULL, sys[0]->G, zero, bn_ctx[0]);

    int counter = 0;

    /*
    *   Initialize the check table
    */
    BIGNUM *tmp = BN_new();
    // the biggest number could transfer
    const int k = 20;
    vector<EC_POINT *> check_table(k+1);
    for(int i=0; i<k+1; i++){
        check_table[i] = EC_POINT_new(sys[0]->curve);
        BN_set_word(tmp,nparties*i);
        EC_POINT_mul(sys[0]->curve, check_table[i], NULL, sys[0]->G, tmp, bn_ctx[0]);
    }


    for(unsigned int i=0; i<sh_CHS.size(); i++){
        // if (EC_POINT_cmp(sys[0]->curve, sh_CHS[i].c2, M, bn_ctx[0]) == 0) {
        //     counter ++;
        // }
        for(int j=0; j<k+1; j++){
            if (EC_POINT_cmp(sys[0]->curve, sh_CHS[i].c2, check_table[j], bn_ctx[0]) == 0) {
                counter += j;
                break;
            }
        }
    }

    BN_free(tmp);

    return counter;
}
/*
*   This implementation implements distributed public key and secrete key generation; distributed decryption; This is a replicate of a previous code I wrote
*   Which original goal is to implement the work of  Distributed Measurement with Private Set-Union Cardinality (ccs17)
*   For this work, we only need the part of verifiable shuffle; it plays by one party and was verifed by another party
*   I just half the communication and computation overhead, because the previous requires each party does the permutation and verification
*   And I do not account the time of distributed key generation and decryption; which substitutately can be assigned by analyzers 
*/
void CP::start(){
    struct timeval t1;
    struct timeval t2;
    double cpu_time_used;
    double total_time_used = 0;

    size_t send_bytes;
    double KB_bytes;
    double total_KB_bytes = 0;

    //log file
    string logFile_name = "run-CP"+ to_string(mynum) +".log";
    ofstream logFile_out(logFile_name.c_str());


    /*
    * step of group key generation
    */
    //gettimeofday(&t1, NULL);
    key_gen();
    //gettimeofday(&t2, NULL);
    // cpu_time_used = (double)(t2.tv_sec-t1.tv_sec)*1000+(double)(t2.tv_usec-t1.tv_usec)/1000;
    // cpu_time_used = cpu_time_used/1000;
    // total_time_used += cpu_time_used;
    // printf("Group key generation phase completes, need:\ttime:\t%f\t(s)\n",cpu_time_used);
    // logFile_out << "Group key generation phase completes, need:\ttime:\t"<< cpu_time_used <<"\t(s)\n";
    // send_bytes = report_size();
    // KB_bytes = send_bytes/1000;
    // total_KB_bytes += KB_bytes;
    // printf("\tcommu:\t%f\t(KB)\n\n",KB_bytes);
    // logFile_out << "\tcommu:\t"<< KB_bytes <<"\t(KB)\n\n";

    // /*
    // * step of aggregate hash table done in data collection phase 
    // */

    /*
    * step of get encrypted hash structure
    */
    share_CHS.resize(n_bins);
    // get_encrypted_HS(share_HS,share_CHS, 0, n_bins);
    //gettimeofday(&t1, NULL);
    multi_thread_get_encrypted_HS(share_HS,share_CHS);
    // gettimeofday(&t2, NULL);
    // cpu_time_used = (double)(t2.tv_sec-t1.tv_sec)*1000+(double)(t2.tv_usec-t1.tv_usec)/1000;
    // cpu_time_used = cpu_time_used/1000;
    // total_time_used += cpu_time_used;
    // printf("Get encrypted hash structure completes, need:\ttime:\t%f\t(s)\n",cpu_time_used);
    // logFile_out << "Get encrypted hash structure completes, need:\ttime:\t"<< cpu_time_used <<"\t(s)\n";
    // send_bytes = report_size();
    // KB_bytes = send_bytes/1000;
    // total_KB_bytes += KB_bytes;
    // printf("\tcommu:\t%f\t(KB)\n\n",KB_bytes);
    // logFile_out << "\tcommu:\t"<< KB_bytes <<"\t(KB)\n\n";

    /*
    * step of shuffling
    */
    //shuffling(share_CHS,0, share_CHS.size());
    gettimeofday(&t1, NULL);
    //multi_thread_shuffling(share_CHS);
    shuffling(share_CHS,0, share_CHS.size());
    gettimeofday(&t2, NULL);
    cpu_time_used = (double)(t2.tv_sec-t1.tv_sec)*1000+(double)(t2.tv_usec-t1.tv_usec)/1000;
    cpu_time_used = cpu_time_used/1000;
    total_time_used += cpu_time_used;
    printf("Shuffling phase completes, need:\ttime:\t%f\t(s)\n",cpu_time_used);
    logFile_out << "Shuffling phase completes, need:\ttime:\t"<< cpu_time_used <<"\t(s)\n";
    send_bytes = report_size();
    KB_bytes = send_bytes/1000;
    total_KB_bytes += KB_bytes;
    printf("\tcommu:\t%f\t(KB)\n\n",KB_bytes);
    logFile_out << "\tcommu:\t"<< KB_bytes <<"\t(KB)\n\n";

    /*
    * step of decrypt
    */
    //decrypt(share_CHS, 0, share_CHS.size());
    //gettimeofday(&t1, NULL);
    multi_thread_decrypt(share_CHS);
    //gettimeofday(&t2, NULL);
    // cpu_time_used = (double)(t2.tv_sec-t1.tv_sec)*1000+(double)(t2.tv_usec-t1.tv_usec)/1000;
    // cpu_time_used = cpu_time_used/1000;
    // total_time_used += cpu_time_used;
    // printf("decrypt phase completes, need:\ttime:\t%f\t(s)\n",cpu_time_used);
    // logFile_out << "decrypt phase completes, need:\ttime:\t"<< cpu_time_used <<"\t(s)\n";
    // send_bytes = report_size();
    // KB_bytes = send_bytes/1000;
    // total_KB_bytes += KB_bytes;
    // printf("\tcommu:\t%f\t(KB)\n\n",KB_bytes);
    // logFile_out << "\tcommu:\t"<< KB_bytes <<"\t(KB)\n\n";

    int result = Output(share_CHS);
    cout<<"To check, we only output the sum of number： "<<result<<endl;
    logFile_out<<"To check, we only output the sum of number： "<<result<<endl;

    printf("Shuffler computation total need:\ttime:\t%f\t(s)\n\n",total_time_used);
    logFile_out << "Shuffler computation total need:\ttime:\t"<< total_time_used <<"\t(s)\n";
    printf("\tShuffler total commu:\t%f\t(KB)\n\n",total_KB_bytes);
    logFile_out << "\tShuffler total commu:\t"<< total_KB_bytes <<"\t(KB)\n\n";


    printf("Output communication: \tcommu:\t%ld\t(Byte)\n\n",sizeof(int)*n_bins);

    logFile_out.close();
}

size_t CP::report_size(){
    size_t sent = 0;
    for(int i=0; i<nthreads; i++){
        sent += thread_player[i]->sent;
        thread_player[i]->sent = 0;
    }
    return sent;
}


void DP_connector::start(std::vector<BIGNUM*>& sh_HS){
    /*
    * Collect the data of each data party orderly
    */
    int i=0;
    int socket_num = -1;
    if (server == 0)
        throw runtime_error("The socket communication failure detection");


    /***********************************Start For benchmark*********************************/
    cout << "************** Start data Collection phase **************" << endl;
    //time measure tools 
    struct timeval t1;
    struct timeval t2;
    double cpu_time_used;
    double KB_bytes;

    if(!sh_HS.empty()){
        int num = sh_HS.size();
        for(int i=0; i<num; i++){
          BN_free(sh_HS[i]);
        }
        sh_HS.clear();
    }
    sh_HS.resize(n_bins);
    for(int i=0; i<n_bins; i++){
        sh_HS[i] = BN_new();
    }

    std::vector<BIGNUM*> tmp_HS(n_bins);
    for(int i=0; i<n_bins; i++){
        tmp_HS[i] = BN_new();
    }
    
    for (i=1; i<=nplayers; i++)
    {
        cerr << "Waiting for Data Party " << i << endl;
        socket_num = server->get_connection_socket(i);
        cerr << "Connected to Data Party " << i << endl;
        
        send(socket_num, GO);


        gettimeofday(&t1, NULL);
        data_collection(socket_num, tmp_HS);
        for(int i=0; i<n_bins; i++){
            BN_mod_add(sh_HS[i], sh_HS[i], tmp_HS[i], mod_q, bn_ctx);
        }
        gettimeofday(&t2, NULL);
        cpu_time_used = (double)(t2.tv_sec-t1.tv_sec)*1000+(double)(t2.tv_usec-t1.tv_usec)/1000;
        printf("data initialization and collection phase: receive %d bins need  %f (ms) \n",n_bins,2*cpu_time_used);
        
        size_t send_bytes = report_size();
        KB_bytes = send_bytes*2/1000;
        printf("\tcommu:\t%f\t(KB)\n\n",KB_bytes);

        KB_bytes = KB_bytes*1000/n_bins;
        printf("Local randomizer communication:  %f (byte) \n",KB_bytes);



        close(socket_num);
        socket_num = -1;
    }

    cout << "************** End Data Collection phase **************" << endl;
}

void DP_connector::init(int _n_bins, int _mynum,int pnb,int _my_port, int _nplayers, const BIGNUM* q){
    n_bins = _n_bins;
    mynum = _mynum;
    portnum_base = pnb;
    nplayers = _nplayers;
    BN_copy(mod_q, q);

    if(_my_port == DP_connector::DEFAULT_PORT){
      my_port = portnum_base+DP_connector::OFFSET_PORT+mynum;
    }
    setup_server();
}

void DP_connector::setup_server()
{
  server = new ServerSocket(my_port);
  server->init();
}

DP_connector::~DP_connector()
{
    if (server != 0){
        delete server;
    }
    BN_CTX_free(bn_ctx);
    BN_free(mod_q);
}

bool DP_connector::data_collection(int socket_num, std::vector<BIGNUM*>& sh_HS){
    if(socket_num == -1){
        throw runtime_error("The socket has been expired");
    }

    octetStream share_stream;
    receive_from(socket_num,share_stream);

    for(int i=0; i<n_bins; i++){
        unpack(sh_HS[i], share_stream);
    }

    return true;       
}

void DP_connector::send_to(int data_player,const octetStream& o,bool donthash) const
{
    TimeScope ts(timer);
    o.Send(data_player);
    if (!donthash)
        { blk_SHA1_Update(&ctx,o.get_data(),o.get_length()); }
    sent += o.get_length();
}

void DP_connector::receive_from(int data_player,octetStream& o,bool donthash) const{
    TimeScope ts(timer);
    o.reset_write_head();
    o.Receive(data_player);
    sent += o.get_length();
    if (!donthash)
        { blk_SHA1_Update(&ctx,o.get_data(),o.get_length()); }
}

size_t DP_connector::report_size(){
    size_t result = sent;
    sent = 0;
    return result;
}