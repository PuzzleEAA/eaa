// (C) 2018 University of NKU. Free for used

/*
 * DataParty.h
 *
 */

#ifndef DATA_PARTY_H_
#define DATA_PARTY_H_


/*
 * @Params of the Class DP
 *		@n_computation_machines 			number of the computation parties
 *		@n_data_machines 					    number of the data parties
 *    @PortnumBase  						    Port number base to attempt to start connections from 
 *		@mynum								        the NO. mark of the current party(numbered in data party)
 *		@my_port							        the port that the server sokcet listening
 *		@hostname							        Host where CP.x is running to collecting data (default: localhost). Ignored if --ip-file-name is used.
 *		@ipFileName         				  Filename containing list of party ip addresses. Alternative to --hostname and running CP.x  data collection.
 *    @lgp                          length of the prime number
 *    @uN                           number of unique items
 *
 */

#include <vector>
#include <string>
#include <pthread.h>
#include "Tools/sha1.h"
#include "Tools/time-func.h"
#include "Tools/octetStream.h"


#include "ElGamal_openssl.h"

class DP
{
private:
	int n_computation_machines;
	int n_data_machines;
  int PortnumBase;
  int mynum;
  int my_port;
  int n_bins;
  std::vector<int> socket_num;
  std::string hostname;
  std::string ipFileName;

  ElGamal* sys;

  int uN;
  int nthreads;

  std::vector<BIGNUM*> Zq_data_table;

  // for safe socket communication
  bool connection_active;
  mutable blk_SHA_CTX ctx;
  mutable size_t sent;
  mutable Timer timer;

public:

	static const int DEFAULT_PORT = -1;
	static const int OFFSET_PORT = 2000;

  DP(int argc, const char** argv);
  ~DP();
  void start();

  bool data_collection();

  bool bucket_share_value(std::vector<BIGNUM*>& data_table);

  void gen_update_data_table(std::vector<BIGNUM*>& data_table);


  
  // // * basic communication functionality
  
  // receive an octetstream from computation player i
  void receive_from(int i,octetStream& o,bool donthash=false) const;

  // Send an octetStream to computation player i
  void send_to(int i,const octetStream& o,bool donthash=false) const;
};



#endif /* DATA_PARTY_H_ */

