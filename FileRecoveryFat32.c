#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<fcntl.h>
#include<unistd.h>
#include<math.h>
#include <sys/mman.h>
#include <openssl/sha.h>
#include <unistd.h>
#include<getopt.h>
#define SHA_DIGEST_LENGTH 20


#pragma pack(push,1)
typedef struct BootEntry {
  unsigned char  BS_jmpBoot[3];     // Assembly instruction to jump to boot code
  unsigned char  BS_OEMName[8];     // OEM Name in ASCII
  unsigned short BPB_BytsPerSec;    // Bytes per sector. Allowed values include 512, 1024, 2048, and 4096
  unsigned char  BPB_SecPerClus;    // Sectors per cluster (data unit). Allowed values are powers of 2, but the cluster size must be 32KB or smaller
  unsigned short BPB_RsvdSecCnt;    // Size in sectors of the reserved area
  unsigned char  BPB_NumFATs;       // Number of FATs
  unsigned short BPB_RootEntCnt;    // Maximum number of files in the root directory for FAT12 and FAT16. This is 0 for FAT32
  unsigned short BPB_TotSec16;      // 16-bit value of number of sectors in file system
  unsigned char  BPB_Media;         // Media type
  unsigned short BPB_FATSz16;       // 16-bit size in sectors of each FAT for FAT12 and FAT16. For FAT32, this field is 0
  unsigned short BPB_SecPerTrk;     // Sectors per track of storage device
  unsigned short BPB_NumHeads;      // Number of heads in storage device
  unsigned int   BPB_HiddSec;       // Number of sectors before the start of partition
  unsigned int   BPB_TotSec32;      // 32-bit value of number of sectors in file system. Either this value or the 16-bit value above must be 0
  unsigned int   BPB_FATSz32;       // 32-bit size in sectors of one FAT
  unsigned short BPB_ExtFlags;      // A flag for FAT
  unsigned short BPB_FSVer;         // The major and minor version number
  unsigned int   BPB_RootClus;      // Cluster where the root directory can be found
  unsigned short BPB_FSInfo;        // Sector where FSINFO structure can be found
  unsigned short BPB_BkBootSec;     // Sector where backup copy of boot sector is located
  unsigned char  BPB_Reserved[12];  // Reserved
  unsigned char  BS_DrvNum;         // BIOS INT13h drive number
  unsigned char  BS_Reserved1;      // Not used
  unsigned char  BS_BootSig;        // Extended boot signature to identify if the next three values are valid
  unsigned int   BS_VolID;          // Volume serial number
  unsigned char  BS_VolLab[11];     // Volume label in ASCII. User defines when creating the file system
  unsigned char  BS_FilSysType[8];  // File system type label in ASCII
} BootEntry;
#pragma pack(pop)

#pragma pack(push,1)
typedef struct DirEntry {
  unsigned char  DIR_Name[11];      // File name
  unsigned char  DIR_Attr;          // File attributes
  unsigned char  DIR_NTRes;         // Reserved
  unsigned char  DIR_CrtTimeTenth;  // Created time (tenths of second)
  unsigned short DIR_CrtTime;       // Created time (hours, minutes, seconds)
  unsigned short DIR_CrtDate;       // Created day
  unsigned short DIR_LstAccDate;    // Accessed day
  unsigned short DIR_FstClusHI;     // High 2 bytes of the first cluster address
  unsigned short DIR_WrtTime;       // Written time (hours, minutes, seconds
  unsigned short DIR_WrtDate;       // Written day
  unsigned short DIR_FstClusLO;     // Low 2 bytes of the first cluster address
  unsigned int   DIR_FileSize;      // File size in bytes. (0 for directories)
} DirEntry;
#pragma pack(pop)

int main(int argc, char **argv){


	int option=0;
	int milestonenumber = 0;
	unsigned int i,j,k,n,w; 
	char redirection[] = ">";
	int newargc=0;
	int filenameindex = 0;
  int sha1index = 0 ;

	// Usage: ./FileRecoveryFat32 disk <options>
	//  -i                     Print the file system information.
	//  -l                     List the root directory.
	//  -r filename [-s sha1]  Recover a contiguous file.
	//  -R filename -s sha1    Recover a possibly non-contiguous file.

	for(i=0;i<argc;i++){
		if(strcmp(argv[i],redirection) == 0 ){
			break;
		}
		else {
			newargc+=1;
		}
	}

	argc = newargc;
	i=0;

	if(argc>6 || argc<3 || argc==5){
		printf("Usage: ./nyufile disk <options>\n  -i                     Print the file system information.\n  -l                     List the root directory.\n  -r filename [-s sha1]  Recover a contiguous file.\n  -R filename -s sha1    Recover a possibly non-contiguous file.\n");
		return 0;
	}

	if(argc==3 && strcmp(argv[2],"-i")!=0 && strcmp(argv[2],"-l")!=0 ){
		printf("Usage: ./nyufile disk <options>\n  -i                     Print the file system information.\n  -l                     List the root directory.\n  -r filename [-s sha1]  Recover a contiguous file.\n  -R filename -s sha1    Recover a possibly non-contiguous file.\n");
		return 0;		
	}

	if(argc==4 && strcmp(argv[2],"-r")!=0){
		printf("Usage: ./nyufile disk <options>\n  -i                     Print the file system information.\n  -l                     List the root directory.\n  -r filename [-s sha1]  Recover a contiguous file.\n  -R filename -s sha1    Recover a possibly non-contiguous file.\n");
		return 0;		
	}

	if(argc==6){

		if(strcmp(argv[2],"-r")==0 && strcmp(argv[4],"-s")==0){

		}

		else if(strcmp(argv[2],"-R")==0 && strcmp(argv[4],"-s")==0){

		}

		else if(strcmp(argv[2],"-s")==0 && strcmp(argv[4],"-r")==0){

		}

		else if(strcmp(argv[2],"-s")==0 && strcmp(argv[4],"-R")==0){

		}

		else {
		printf("Usage: ./nyufile disk <options>\n  -i                     Print the file system information.\n  -l                     List the root directory.\n  -r filename [-s sha1]  Recover a contiguous file.\n  -R filename -s sha1    Recover a possibly non-contiguous file.\n");
		return 0;				
		}
	}


	while( (option = getopt(argc,argv,"ilr:R:s:") ) != -1) {

		switch(option){

  		case 'i' :

  			if(argc>3){
						printf("Usage: ./nyufile disk <options>\n  -i                     Print the file system information.\n  -l                     List the root directory.\n  -r filename [-s sha1]  Recover a contiguous file.\n  -R filename -s sha1    Recover a possibly non-contiguous file.\n");
  				return 0;
  				
  			}
  			milestonenumber = 2;
  			break;

  		case 'l' :  

  			if(argc>3){
						printf("Usage: ./nyufile disk <options>\n  -i                     Print the file system information.\n  -l                     List the root directory.\n  -r filename [-s sha1]  Recover a contiguous file.\n  -R filename -s sha1    Recover a possibly non-contiguous file.\n");
  				return 0;
  			}

  			milestonenumber = 3;
  			break;                 
  		
  		case 'r' :

  			if(strcmp(argv[2],"-r")==0){

  				if(argc==6 && strcmp(argv[4],"-s")==0){
		  					filenameindex = 2;
		  					sha1index = 4;
  					milestonenumber = 7;
  				} 

  				else if(argc==4){
  					milestonenumber = 4;
  				}

  				else{
						printf("Usage: ./nyufile disk <options>\n  -i                     Print the file system information.\n  -l                     List the root directory.\n  -r filename [-s sha1]  Recover a contiguous file.\n  -R filename -s sha1    Recover a possibly non-contiguous file.\n");
  					return 0; 					
  				}

  			}

  			else if(argc==6 && strcmp(argv[4],"-r")==0){
  				//printf("2\n");
  				if(strcmp(argv[1],"-s")==0){
  					filenameindex = 4;
		  					sha1index = 2;
  					milestonenumber = 7;
  				}

  				else{
						printf("Usage: ./nyufile disk <options>\n  -i                     Print the file system information.\n  -l                     List the root directory.\n  -r filename [-s sha1]  Recover a contiguous file.\n  -R filename -s sha1    Recover a possibly non-contiguous file.\n");
  					return 0; 
  				}

  			}


  			else{
  					printf("Usage: ./nyufile disk <options>\n  -i                     Print the file system information.\n  -l                     List the root directory.\n  -r filename [-s sha1]  Recover a contiguous file.\n  -R filename -s sha1    Recover a possibly non-contiguous file.\n");
  				return 0; 

  			}

  			break;

  		case 'R' :

  			if(argc==6 && strcmp(argv[2],"-R")==0){
  				if(strcmp(argv[4],"-s")==0){
  					filenameindex = 2;
		  					sha1index = 4;
  					milestonenumber = 8;
  				}

  				else{
						printf("Usage: ./nyufile disk <options>\n  -i                     Print the file system information.\n  -l                     List the root directory.\n  -r filename [-s sha1]  Recover a contiguous file.\n  -R filename -s sha1    Recover a possibly non-contiguous file.\n");
	  				return 0;
  				}
  			}

  			else if(argc==6 && strcmp(argv[4],"-R")==0){

  				if( strcmp(argv[1],"-s")==0){
  					filenameindex = 4;
		  					sha1index = 2;
  					milestonenumber = 8;
  				}

  				else{
							printf("Usage: ./nyufile disk <options>\n  -i                     Print the file system information.\n  -l                     List the root directory.\n  -r filename [-s sha1]  Recover a contiguous file.\n  -R filename -s sha1    Recover a possibly non-contiguous file.\n");
	  				return 0;
  					
  				}
  			}

  			else{
						printf("Usage: ./nyufile disk <options>\n  -i                     Print the file system information.\n  -l                     List the root directory.\n  -r filename [-s sha1]  Recover a contiguous file.\n  -R filename -s sha1    Recover a possibly non-contiguous file.\n");
  				return 0;
  			}
  			break;

  		case 's' : 
  				continue;

  		default :
					printf("Usage: ./nyufile disk <options>\n  -i                     Print the file system information.\n  -l                     List the root directory.\n  -r filename [-s sha1]  Recover a contiguous file.\n  -R filename -s sha1    Recover a possibly non-contiguous file.\n");
			return 0;
		}
	}

		int fd;
		off_t sizeofdisk;
		struct stat bufferstats;
		if((fd = open(argv[argc-1],O_RDWR)) < 0){
			perror("Failed to Open the Disk");
		}


		fstat(fd,&bufferstats);
		sizeofdisk = bufferstats.st_size;	

		unsigned int sizeofdisk1 = sizeofdisk;

   	unsigned char*	mappingoffile = mmap(NULL,sizeofdisk1,PROT_READ | PROT_WRITE,MAP_SHARED,fd,0);
   	BootEntry bootsector_ofdisk;

   	memcpy(&bootsector_ofdisk,&mappingoffile[0],90);

    unsigned int no_of_fats = bootsector_ofdisk.BPB_NumFATs;
   	unsigned int no_of_bytespersector = bootsector_ofdisk.BPB_BytsPerSec;
    unsigned int no_of_sectorspercluster = bootsector_ofdisk.BPB_SecPerClus;
    unsigned int no_of_reservedsectors = bootsector_ofdisk.BPB_RsvdSecCnt;

   	unsigned int directory_entries_percluster = (no_of_bytespersector*no_of_sectorspercluster)/32;

    unsigned int rootcluster = bootsector_ofdisk.BPB_RootClus;

    unsigned int fat_size_insectors = bootsector_ofdisk.BPB_FATSz32;
    unsigned int fat_size_inbytes = fat_size_insectors*no_of_bytespersector;
    unsigned int no_of_fat_entries = fat_size_inbytes/4;

    unsigned int fat1_area_startingindex = no_of_reservedsectors*no_of_bytespersector;

    unsigned int data_area_startingindex = (no_of_reservedsectors+(fat_size_insectors*no_of_fats))*no_of_bytespersector;

    size_t cluster_size_bytes = no_of_sectorspercluster*no_of_bytespersector;


    DirEntry rootdir_Entrylist;

   	unsigned char* templistfilename = (unsigned char*)calloc(12,sizeof(unsigned char));

   	int listfilenameindex=0;

   	unsigned char spacechar[] = " ";
   	char dotchar[] = ".";

    unsigned int **fat_table;

    fat_table = (unsigned int**)calloc(no_of_fats,sizeof(unsigned int*));

		for(i=0;i<no_of_fats;i++){
		    fat_table[i] = (unsigned int*)calloc(no_of_fat_entries,sizeof(unsigned int));
		}

    k = fat1_area_startingindex;

    for(i=0;i<no_of_fats;i++){

    	for(j=0;j<no_of_fat_entries;j++){

    		memcpy(&fat_table[i][j],&mappingoffile[k],4);
    		k = k + 4;
    	}
    }

   if(milestonenumber==2){

   	   	printf("Number of FATs = %d\n",no_of_fats); 
   	   	printf("Number of bytes per sector = %d\n",no_of_bytespersector); 
   	   	printf("Number of sectors per cluster = %d\n",no_of_sectorspercluster); 
   	   	printf("Number of reserved sectors = %d\n",no_of_reservedsectors); 
   	   	fflush(stdout);

		return 0;

   }

   if(milestonenumber==3){
   	   	
   	   	unsigned int clustercount_from_FAT=0;
   	   	unsigned int m;
   	   	m = rootcluster;
   	   	clustercount_from_FAT =1;
   	   	while(fat_table[0][m]<0x0ffffff8){
   	   		m = fat_table[0][m];
   	   		clustercount_from_FAT+=1;
   	   	}

   	   	unsigned int fileclusterarray[clustercount_from_FAT+1];

   	   	m = rootcluster;

   	   	clustercount_from_FAT =1;
   	   	fileclusterarray[0]=rootcluster;

   	   	while(fat_table[0][m]<0x0ffffff8){
   	   		m = fat_table[0][m];
   	   		fileclusterarray[clustercount_from_FAT] = m;
   	   		 clustercount_from_FAT+=1;
   	   	}
   	   	
   	   	unsigned int sizeoffile;
   	   	unsigned int high2;
   	   	unsigned int low2 ;
   	   	unsigned int startingcluster_file;
   	   	unsigned char *filelistname;

   	   	unsigned totalentries =0;

   	   	for( i=0;i < clustercount_from_FAT;i++){
   	   		for( k=0; k< directory_entries_percluster; k++){

   	   			memcpy(&rootdir_Entrylist,&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((fileclusterarray[i]-2)*no_of_bytespersector*no_of_sectorspercluster)+(k*32)],32);

   	   			if(rootdir_Entrylist.DIR_Name[0]!=0x00){
   	   				if(rootdir_Entrylist.DIR_Name[0]!=0xe5){  
		   	   			sizeoffile = rootdir_Entrylist.DIR_FileSize;
		   	   			high2 = rootdir_Entrylist.DIR_FstClusHI ;
		   	   			low2 = rootdir_Entrylist.DIR_FstClusLO ;
		   	   			startingcluster_file =  ( high2 << 16 )+ low2;

		   	   			for(n=0;n<8;n++){

		   	   				if(rootdir_Entrylist.DIR_Name[n]==spacechar[0]){
		   	   					break;
		   	   				}
		   	   				else{
		   	   					templistfilename[listfilenameindex]=rootdir_Entrylist.DIR_Name[n];
		   	   					listfilenameindex+=1;
		   	   				}
		   	   			}

		   	   			if(rootdir_Entrylist.DIR_Name[8]!=spacechar[0]){
							templistfilename[listfilenameindex]=dotchar[0];
		   	   				listfilenameindex+=1;		  
		 	   			}

		   	   			for(n=8;n<11;n++){

		   	   				if(rootdir_Entrylist.DIR_Name[n]==spacechar[0]){
		   	   					break;
		   	   				}
		   	   				else{
		   	   					templistfilename[listfilenameindex]=rootdir_Entrylist.DIR_Name[n];
		   	   					listfilenameindex+=1;
		   	   				}
		   	   			}

		   	   			filelistname = (unsigned char*)calloc(listfilenameindex,sizeof(unsigned char));


		   	   			for(n=0;n<listfilenameindex;n++){
		   	   				filelistname[n]=templistfilename[n];
		   	   			}

		   	   			if(rootdir_Entrylist.DIR_Attr == 16){
		   	   				fprintf(stdout,"%.*s/ (size = %d, starting cluster = %d)\n",listfilenameindex,filelistname,sizeoffile,startingcluster_file);
		   	   				fflush(stdout);
		   	   				totalentries+=1;
		   	   			}

		   	   			else{
		   	   				fprintf(stdout,"%.*s (size = %d, starting cluster = %d)\n",listfilenameindex,filelistname,sizeoffile,startingcluster_file);
		   	   				fflush(stdout);
		   	   				totalentries+=1;
		   	   			}

		   	   			listfilenameindex=0;
		   	   			free(filelistname);		   	   			
   	   				}
   	   			}

   	   			else{
   	   				printf("Total number of entries = %d\n",totalentries);
   	   				fflush(stdout);
   	   				return 0;
   	   			}

   	   		}
   	   	}
   	   	printf("Total number of entries = %d\n",totalentries);
   	   	fflush(stdout);
     	return 0;

   }

   if(milestonenumber==4){
   	
   		int lengthoffilename = strlen(argv[2]);

   		int matchingfilecount=0;

   		char modifiedfilename[lengthoffilename];

   		modifiedfilename[0]=0xe5;

   		for(i=1;i<lengthoffilename;i++){

   			modifiedfilename[i]=argv[2][i];

   		}
   
   		unsigned int clustercount_from_FAT=0;
   	   	unsigned int m;
   	   	m = rootcluster;
   	   	clustercount_from_FAT =1;
   	   	while(fat_table[0][m]<0x0ffffff8){
   	   		m = fat_table[0][m];
   	   		clustercount_from_FAT+=1;
   	   	}

   	   	unsigned int fileclusterarray[clustercount_from_FAT+1];

   	   	m = rootcluster;

   	   	clustercount_from_FAT =1;
   	   	fileclusterarray[0]=rootcluster;

   	   	while(fat_table[0][m]<0x0ffffff8){
   	   		m = fat_table[0][m];
   	   		fileclusterarray[clustercount_from_FAT] = m;
   	   		 clustercount_from_FAT+=1;
   	   	}

   	   	unsigned int size_matchedfile;
   	   	unsigned int startingcluster_matchedfile;
   	   	unsigned int firstcharaddress;

				unsigned int sizeoffile;
   	   	unsigned int high2;
   	   	unsigned int low2 ;
   	   	unsigned int startingcluster_file;
   	   	unsigned char *filelistname;
   	   	unsigned totalentries =0;

   	   	for( i=0;i < clustercount_from_FAT;i++){
   	   		for( k=0; k< directory_entries_percluster; k++){

   	   			memcpy(&rootdir_Entrylist,&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((fileclusterarray[i]-2)*no_of_bytespersector*no_of_sectorspercluster)+(k*32)],32);

   	   			if(rootdir_Entrylist.DIR_Name[0]!=0x00){
   	   				if(rootdir_Entrylist.DIR_Name[0]==0xe5){
		   	   			sizeoffile = rootdir_Entrylist.DIR_FileSize;
		   	   			high2 = rootdir_Entrylist.DIR_FstClusHI ;
		   	   			low2 = rootdir_Entrylist.DIR_FstClusLO ;
		   	   			startingcluster_file =  ( high2 << 16 )+ low2;

		   	   			for(n=0;n<8;n++){

		   	   				if(rootdir_Entrylist.DIR_Name[n]==spacechar[0]){
		   	   					break;
		   	   				}
		   	   				else{
		   	   					templistfilename[listfilenameindex]=rootdir_Entrylist.DIR_Name[n];
		   	   					listfilenameindex+=1;
		   	   				}
		   	   			}

		   	   			if(rootdir_Entrylist.DIR_Name[8]!=spacechar[0]){
								templistfilename[listfilenameindex]=dotchar[0];
		   	   				listfilenameindex+=1;		  
		 	   				}

		   	   			for(n=8;n<11;n++){

		   	   				if(rootdir_Entrylist.DIR_Name[n]==spacechar[0]){
		   	   					break;
		   	   				}
		   	   				else{
		   	   					templistfilename[listfilenameindex]=rootdir_Entrylist.DIR_Name[n];
		   	   					listfilenameindex+=1;
		   	   				}
		   	   			}

		   	   			filelistname = (unsigned char*)calloc(listfilenameindex,sizeof(unsigned char));

		   	   			for(n=0;n<listfilenameindex;n++){
		   	   				filelistname[n]=templistfilename[n];
		   	   			}


		   	   			if(rootdir_Entrylist.DIR_Attr != 16){

		   	   				if(lengthoffilename==listfilenameindex && strncmp(modifiedfilename,filelistname,lengthoffilename)==0){

		   	   					matchingfilecount+=1;
		   	   					size_matchedfile = sizeoffile;
		   	   					startingcluster_matchedfile = startingcluster_file;
		   	   					firstcharaddress = (no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((fileclusterarray[i]-2)*no_of_bytespersector*no_of_sectorspercluster)+(k*32);

		   	   					if(matchingfilecount>1){
		   	   						printf("%.*s: multiple candidates found\n",lengthoffilename,argv[2]);
		   	   						fflush(stdout);
		   	   						return 0;
		   	   					}
   								}


		   	   			}		   	   			

		   	   			listfilenameindex=0;
		   	   			free(filelistname);

   	   				}
   	   			}

   	   			else{
   	   					if(matchingfilecount==0){
   	   						printf("%.*s: file not found\n",lengthoffilename,argv[2]);
   	   						fflush(stdout);
   	   						return 0;
   	   					}

   	   					unsigned int no_of_clusters_matchedfile;

   	   					if(size_matchedfile%(no_of_bytespersector*no_of_sectorspercluster) == 0){

   	   						no_of_clusters_matchedfile = size_matchedfile/(no_of_bytespersector*no_of_sectorspercluster);

   	   					}
   	   					else {
   	   						  	no_of_clusters_matchedfile = (size_matchedfile/(no_of_bytespersector*no_of_sectorspercluster)) + 1 ;
   	   					}

   	   					memcpy(&mappingoffile[firstcharaddress],&argv[2][0],1);

   	   					unsigned int x,y,z;

   	   					if(size_matchedfile==0){

   	   						printf("%.*s: successfully recovered\n",lengthoffilename,argv[2]);
   	   						return 0;

   	   					}

   	   					for(x=startingcluster_matchedfile;x<(no_of_clusters_matchedfile+startingcluster_matchedfile-1);x++){

   	   						for(y=0;y<no_of_fats;y++){

   	   							fat_table[y][x] = (x+1);

   	   						}

   	   					}

   	   					for(y=0;y<no_of_fats;y++){

   	   							fat_table[y][startingcluster_matchedfile+no_of_clusters_matchedfile-1] = 0x0ffffff9;

   	   						}

   	   						y = fat1_area_startingindex;

						    for(x=0;x<no_of_fats;x++){

						    	for(z=0;z<no_of_fat_entries;z++){

						    		memcpy(&mappingoffile[y],&fat_table[x][z],4);
						    		y = y + 4;
						    	}
						    }

   	   				printf("%.*s: successfully recovered\n",lengthoffilename,argv[2]);
   	   				return 0;
   	   			}
   	   		}
   	   	}

   	   	if(matchingfilecount==0){
   	   						printf("%.*s: file not found\n",lengthoffilename,argv[2]);
   	   						fflush(stdout);
   	   						return 0;
   	   					}

   	   					unsigned int no_of_clusters_matchedfile;

   	   					if(size_matchedfile%(no_of_bytespersector*no_of_sectorspercluster) == 0){

   	   						no_of_clusters_matchedfile = size_matchedfile/(no_of_bytespersector*no_of_sectorspercluster);

   	   					}
   	   					else {

   	   						  	no_of_clusters_matchedfile = (size_matchedfile/(no_of_bytespersector*no_of_sectorspercluster)) + 1 ;
   	   					}

   	   					memcpy(&mappingoffile[firstcharaddress],&argv[2][0],1);

   	   					unsigned int x,y,z;

   	   					if(size_matchedfile==0){

   	   						printf("%.*s: successfully recovered\n",lengthoffilename,argv[2]);
   	   						return 0;

   	   					}

   	   					for(x=startingcluster_matchedfile;x<(no_of_clusters_matchedfile+startingcluster_matchedfile-1);x++){

   	   						for(y=0;y<no_of_fats;y++){

   	   							fat_table[y][x] = (x+1);

   	   						}

   	   					}

   	   					for(y=0;y<no_of_fats;y++){

   	   							fat_table[y][startingcluster_matchedfile+no_of_clusters_matchedfile-1] = 0x0ffffff9;

   	   						}

   	   						y = fat1_area_startingindex;

						    for(x=0;x<no_of_fats;x++){

						    	for(z=0;z<no_of_fat_entries;z++){

						    		memcpy(&mappingoffile[y],&fat_table[x][z],4);
						    		y = y + 4;
						    	}
						    }

   	   				printf("%.*s: successfully recovered\n",lengthoffilename,argv[2]);
 
   	   				return 0;

   }

   if(milestonenumber==7){

   	int lengthoffilename = strlen(argv[filenameindex]);

   		int matchingfilecount=0;

   		char modifiedfilename[lengthoffilename];

   		modifiedfilename[0]=0xe5;

   		for(i=1;i<lengthoffilename;i++){

   			modifiedfilename[i]=argv[filenameindex][i];

   		}
   	
   		unsigned int clustercount_from_FAT=0;
   	   	unsigned int m;
   	   	m = rootcluster;
   	   	clustercount_from_FAT =1;
   	   	while(fat_table[0][m]<0x0ffffff8){
   	   		m = fat_table[0][m];
   	   		clustercount_from_FAT+=1;
   	   	}

   	   	unsigned int fileclusterarray[clustercount_from_FAT+1];

   	   	m = rootcluster;

   	   	clustercount_from_FAT =1;
   	   	fileclusterarray[0]=rootcluster;

   	   	while(fat_table[0][m]<0x0ffffff8){
   	   		m = fat_table[0][m];
   	   		fileclusterarray[clustercount_from_FAT] = m;
   	   		 clustercount_from_FAT+=1;
   	   	}

   	   	unsigned int size_matchedfile;
   	   	unsigned int startingcluster_matchedfile;
   	   	unsigned int firstcharaddress;

   	   	unsigned int sizeoffile;
   	   	size_t sha_sizeoffile;
   	   	unsigned int high2;
   	   	unsigned int low2 ;
   	   	unsigned int startingcluster_file;
   	   	unsigned char* filelistname;

   	   	unsigned totalentries =0;

   	   	unsigned char given_sha1[20];
   	   	unsigned char *list_sha1;
   	   	unsigned char empty_sha1[40] = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
   	   	unsigned char sha_calc_array[40];


   	   	for(i=0;i<40;i++){

   	   		if(argv[sha1index][i] == '0'){
   	   			 sha_calc_array[i] = 0 ;
   	   		}

   	   		if(argv[sha1index][i] == '1'){
   	   			 sha_calc_array[i] = 1 ;
   	   		}

   	   		if(argv[sha1index][i] == '2'){
   	   			 sha_calc_array[i] = 2 ;
   	   		}

   	   		if(argv[sha1index][i] == '3'){
   	   			 sha_calc_array[i] = 3 ;
   	   		}
   	   		if(argv[sha1index][i] == '4'){
   	   			 sha_calc_array[i] = 4 ;
   	   		}
   	   		if(argv[sha1index][i] == '5'){
   	   			 sha_calc_array[i] = 5 ;
   	   		}
   	   		if(argv[sha1index][i] == '6'){
   	   			 sha_calc_array[i] = 6 ;
   	   		}
   	   		if(argv[sha1index][i] == '7'){
   	   			 sha_calc_array[i] = 7 ;
   	   		}
   	   		if(argv[sha1index][i] == '8'){
   	   			 sha_calc_array[i] = 8 ;
   	   		}
   	   		if(argv[sha1index][i] == '9'){
   	   			 sha_calc_array[i] = 9 ;
   	   		}
   	   		if(argv[sha1index][i] == 'a'){
   	   			 sha_calc_array[i] = 10 ;
   	   		}
   	   		if(argv[sha1index][i] == 'b'){
   	   			 sha_calc_array[i] = 11 ;
   	   		}
   	   		if(argv[sha1index][i] == 'c'){
   	   			 sha_calc_array[i] = 12 ;
   	   		}
   	   		if(argv[sha1index][i] == 'd'){
   	   			 sha_calc_array[i] = 13 ;
   	   		}
   	   		if(argv[sha1index][i] == 'e'){
   	   			 sha_calc_array[i] = 14 ;
   	   		}
   	   		if(argv[sha1index][i] == 'f'){
   	   			 sha_calc_array[i] = 15 ;
   	   		}

   	   	}

   	   	for(i=0;i<20;i++){

   	   		given_sha1[i] = ((sha_calc_array[2*i] & 0x0000ffff ) << 4)+((sha_calc_array[(2*i)+1]) & 0x0000ffff) ;

   	   	}

   	   	for( i=0;i < clustercount_from_FAT;i++){
   	   		for( k=0; k< directory_entries_percluster; k++){

   	   			memcpy(&rootdir_Entrylist,&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((fileclusterarray[i]-2)*no_of_bytespersector*no_of_sectorspercluster)+(k*32)],32);

   	   			if(rootdir_Entrylist.DIR_Name[0]!=0x00){
   	   				if(rootdir_Entrylist.DIR_Name[0]==0xe5){
		   	   			sizeoffile = rootdir_Entrylist.DIR_FileSize;
		   	   			high2 = rootdir_Entrylist.DIR_FstClusHI ;
		   	   			low2 = rootdir_Entrylist.DIR_FstClusLO ;
		   	   			startingcluster_file =  ( high2 << 16 )+ low2;

		   	   			for(n=0;n<8;n++){

		   	   				if(rootdir_Entrylist.DIR_Name[n]==spacechar[0]){
		   	   					break;
		   	   				}
		   	   				else{
		   	   					templistfilename[listfilenameindex]=rootdir_Entrylist.DIR_Name[n];
		   	   					listfilenameindex+=1;
		   	   				}
		   	   			}

		   	   			if(rootdir_Entrylist.DIR_Name[8]!=spacechar[0]){
								templistfilename[listfilenameindex]=dotchar[0];
		   	   				listfilenameindex+=1;		  
		 	   				}

		   	   			for(n=8;n<11;n++){

		   	   				if(rootdir_Entrylist.DIR_Name[n]==spacechar[0]){
		   	   					break;
		   	   				}
		   	   				else{
		   	   					templistfilename[listfilenameindex]=rootdir_Entrylist.DIR_Name[n];
		   	   					listfilenameindex+=1;
		   	   				}
		   	   			}

		   	   			filelistname = (unsigned char*)calloc(listfilenameindex,sizeof(unsigned char));

		   	   			for(n=0;n<listfilenameindex;n++){
		   	   				filelistname[n]=templistfilename[n];
		   	   			}

		   	   			if(rootdir_Entrylist.DIR_Attr != 16){
		   	   			

		   	   				if(lengthoffilename==listfilenameindex && strncmp(modifiedfilename,filelistname,lengthoffilename)==0){

		   	   						unsigned char list_file[sizeoffile+100];

		   	   						list_sha1 = (unsigned char*)calloc(20, sizeof(unsigned char));

		   	   						if(sizeoffile==0){

		   	   							for(w=0;w<40;w++){

									   	   		if(empty_sha1[w] == '0'){
									   	   			 sha_calc_array[w] = 0 ;
									   	   		}

									   	   		if(empty_sha1[w] == '1'){
									   	   			 sha_calc_array[w] = 1 ;
									   	   		}

									   	   		if(empty_sha1[w] == '2'){
									   	   			 sha_calc_array[w] = 2 ;
									   	   		}

									   	   		if(empty_sha1[w] == '3'){
									   	   			 sha_calc_array[w] = 3 ;
									   	   		}
									   	   		if(empty_sha1[w] == '4'){
									   	   			 sha_calc_array[w] = 4 ;
									   	   		}
									   	   		if(empty_sha1[w] == '5'){
									   	   			 sha_calc_array[w] = 5 ;
									   	   		}
									   	   		if(empty_sha1[w] == '6'){
									   	   			 sha_calc_array[w] = 6 ;
									   	   		}
									   	   		if(empty_sha1[w] == '7'){
									   	   			 sha_calc_array[w] = 7 ;
									   	   		}
									   	   		if(empty_sha1[w] == '8'){
									   	   			 sha_calc_array[w] = 8 ;
									   	   		}
									   	   		if(empty_sha1[w] == '9'){
									   	   			 sha_calc_array[w] = 9 ;
									   	   		}
									   	   		if(empty_sha1[w] == 'a'){
									   	   			 sha_calc_array[w] = 10 ;
									   	   		}
									   	   		if(empty_sha1[w] == 'b'){
									   	   			 sha_calc_array[w] = 11 ;
									   	   		}
									   	   		if(empty_sha1[w] == 'c'){
									   	   			 sha_calc_array[w] = 12 ;
									   	   		}
									   	   		if(empty_sha1[w] == 'd'){
									   	   			 sha_calc_array[w] = 13 ;
									   	   		}
									   	   		if(empty_sha1[w] == 'e'){
									   	   			 sha_calc_array[w] = 14 ;
									   	   		}
									   	   		if(empty_sha1[w] == 'f'){
									   	   			 sha_calc_array[w] = 15 ;
									   	   		}

									   	   	}

		   	   							for(w=0;w<20;w++){
									   	   		list_sha1[w] = (sha_calc_array[2*w] << 4)+(sha_calc_array[(2*w)+1]) ;
									   	   	}
		   	   						}
		   	   						if(sizeoffile>0){

		   	   						
		   	   						sha_sizeoffile = sizeoffile;

		   	   						memcpy(&list_file,&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((startingcluster_file-2)*no_of_bytespersector*no_of_sectorspercluster)],sha_sizeoffile);		   	   					 
		   	   					
		   	   					  SHA1(list_file, sha_sizeoffile, list_sha1);

		   	   					}

		   	   					if(strncmp(list_sha1,given_sha1, 20)==0){	  	   			
			   	   					matchingfilecount+=1;
			   	   					size_matchedfile = sizeoffile;
			   	   					startingcluster_matchedfile = startingcluster_file;
			   	   					firstcharaddress = (no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((fileclusterarray[i]-2)*no_of_bytespersector*no_of_sectorspercluster)+(k*32);
		   	   				}
		   	   					
		   	   					free(list_sha1);

		   	   					if(matchingfilecount>1){
		   	   						printf("%.*s: multiple candidates found\n",lengthoffilename,argv[filenameindex]);
		   	   						fflush(stdout);
		   	   						return 0;
		   	   					}
   								}

		   	   			}

		   	   			listfilenameindex=0;
		   	   			free(filelistname);
   	   				}
   	   			}

   	   			else{
   	   						// Do the recovery part - Milestone 4,5 - Here.

   	   					if(matchingfilecount==0){
   	   						printf("%.*s: file not found\n",lengthoffilename,argv[filenameindex]);
   	   						fflush(stdout);
   	   						return 0;
   	   					}

   	   					unsigned int no_of_clusters_matchedfile;

   	   					if(size_matchedfile%(no_of_bytespersector*no_of_sectorspercluster) == 0){

   	   						no_of_clusters_matchedfile = size_matchedfile/(no_of_bytespersector*no_of_sectorspercluster);

   	   					}
   	   					else {
   	   						  	no_of_clusters_matchedfile = (size_matchedfile/(no_of_bytespersector*no_of_sectorspercluster)) + 1 ;
   	   					}
   	   						memcpy(&mappingoffile[firstcharaddress],&argv[filenameindex][0],1);

   	   					unsigned int x,y,z;

   	   					if(size_matchedfile==0){

   	   						printf("%.*s: successfully recovered with SHA-1\n",lengthoffilename,argv[filenameindex]);
   	   						return 0;

   	   					}

   	   					for(x=startingcluster_matchedfile;x<(no_of_clusters_matchedfile+startingcluster_matchedfile-1);x++){

   	   						for(y=0;y<no_of_fats;y++){

   	   							fat_table[y][x] = (x+1);

   	   						}

   	   					}

   	   					for(y=0;y<no_of_fats;y++){

   	   							fat_table[y][startingcluster_matchedfile+no_of_clusters_matchedfile-1] = 0x0ffffff9;

   	   						}

   	   						y = fat1_area_startingindex;

						    for(x=0;x<no_of_fats;x++){

						    	for(z=0;z<no_of_fat_entries;z++){

						    		memcpy(&mappingoffile[y],&fat_table[x][z],4);
						    		y = y + 4;
						    	}
						    }

   	   				printf("%.*s: successfully recovered with SHA-1\n",lengthoffilename,argv[filenameindex]);
   	   				return 0;
   	   			}



   	   		}
   	   	}

   	   	if(matchingfilecount==0){
   	   						printf("%.*s: file not found\n",lengthoffilename,argv[filenameindex]);
   	   						fflush(stdout);
   	   						return 0;
   	   					}

   	   					unsigned int no_of_clusters_matchedfile;

   	   					if(size_matchedfile%(no_of_bytespersector*no_of_sectorspercluster) == 0){

   	   						no_of_clusters_matchedfile = size_matchedfile/(no_of_bytespersector*no_of_sectorspercluster);

   	   					}
   	   					else {

   	   						  	no_of_clusters_matchedfile = (size_matchedfile/(no_of_bytespersector*no_of_sectorspercluster)) + 1 ;


   	   					}

   	   						memcpy(&mappingoffile[firstcharaddress],&argv[filenameindex][0],1);

   	   					unsigned int x,y,z;

   	   					if(size_matchedfile==0){

   	   						printf("%.*s: successfully recovered with SHA-1\n",lengthoffilename,argv[filenameindex]);
   	   						return 0;

   	   					}

   	   					for(x=startingcluster_matchedfile;x<(no_of_clusters_matchedfile+startingcluster_matchedfile-1);x++){

   	   						for(y=0;y<no_of_fats;y++){

   	   							fat_table[y][x] = (x+1);

   	   						}

   	   					}

   	   					for(y=0;y<no_of_fats;y++){

   	   							fat_table[y][startingcluster_matchedfile+no_of_clusters_matchedfile-1] = 0x0ffffff9;

   	   						}

   	   						y = fat1_area_startingindex;

						    for(x=0;x<no_of_fats;x++){

						    	for(z=0;z<no_of_fat_entries;z++){

						    		memcpy(&mappingoffile[y],&fat_table[x][z],4);
						    		y = y + 4;
						    	}
						    }

   	   				printf("%.*s: successfully recovered with SHA-1\n",lengthoffilename,argv[filenameindex]);
   	   				return 0;

   }

   if(milestonenumber==8){

			int lengthoffilename = strlen(argv[filenameindex]);

   		int matchingfilecount=0;

   		char modifiedfilename[lengthoffilename];

   		modifiedfilename[0]=0xe5;

   		for(i=1;i<lengthoffilename;i++){

   			modifiedfilename[i]=argv[filenameindex][i];

   		}
   	

   		unsigned int clustercount_from_FAT=0;
   	   	unsigned int m;
   	   	m = rootcluster;
   	   	clustercount_from_FAT =1;
   	   	while(fat_table[0][m]<0x0ffffff8){
   	   		m = fat_table[0][m];
   	   		clustercount_from_FAT+=1;
   	   	}

   	   	unsigned int fileclusterarray[clustercount_from_FAT+1];

   	   	m = rootcluster;

   	   	clustercount_from_FAT =1;
   	   	fileclusterarray[0]=rootcluster;

   	   	while(fat_table[0][m]<0x0ffffff8){
   	   		m = fat_table[0][m];
   	   		fileclusterarray[clustercount_from_FAT] = m;
   	   		 clustercount_from_FAT+=1;
   	   	}


   	   	unsigned int size_matchedfile;
   	   	unsigned int startingcluster_matchedfile;
   	   	unsigned int firstcharaddress;

   	   	unsigned int sizeoffile;
   	   	size_t sha_sizeoffile;
   	   	unsigned int high2;
   	   	unsigned int low2 ;
   	   	unsigned int startingcluster_file;
   	   	unsigned char* filelistname;

   	   	unsigned totalentries =0;

   	   	unsigned char given_sha1[20];
   	   	unsigned char *list_sha1;
   	   	unsigned char empty_sha1[40] = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
   	   	unsigned char sha_calc_array[40];


   	   	for(i=0;i<40;i++){

   	   		if(argv[sha1index][i] == '0'){
   	   			 sha_calc_array[i] = 0 ;
   	   		}

   	   		if(argv[sha1index][i] == '1'){
   	   			 sha_calc_array[i] = 1 ;
   	   		}

   	   		if(argv[sha1index][i] == '2'){
   	   			 sha_calc_array[i] = 2 ;
   	   		}

   	   		if(argv[sha1index][i] == '3'){
   	   			 sha_calc_array[i] = 3 ;
   	   		}
   	   		if(argv[sha1index][i] == '4'){
   	   			 sha_calc_array[i] = 4 ;
   	   		}
   	   		if(argv[sha1index][i] == '5'){
   	   			 sha_calc_array[i] = 5 ;
   	   		}
   	   		if(argv[sha1index][i] == '6'){
   	   			 sha_calc_array[i] = 6 ;
   	   		}
   	   		if(argv[sha1index][i] == '7'){
   	   			 sha_calc_array[i] = 7 ;
   	   		}
   	   		if(argv[sha1index][i] == '8'){
   	   			 sha_calc_array[i] = 8 ;
   	   		}
   	   		if(argv[sha1index][i] == '9'){
   	   			 sha_calc_array[i] = 9 ;
   	   		}
   	   		if(argv[sha1index][i] == 'a'){
   	   			 sha_calc_array[i] = 10 ;
   	   		}
   	   		if(argv[sha1index][i] == 'b'){
   	   			 sha_calc_array[i] = 11 ;
   	   		}
   	   		if(argv[sha1index][i] == 'c'){
   	   			 sha_calc_array[i] = 12 ;
   	   		}
   	   		if(argv[sha1index][i] == 'd'){
   	   			 sha_calc_array[i] = 13 ;
   	   		}
   	   		if(argv[sha1index][i] == 'e'){
   	   			 sha_calc_array[i] = 14 ;
   	   		}
   	   		if(argv[sha1index][i] == 'f'){
   	   			 sha_calc_array[i] = 15 ;
   	   		}

   	   	}

   	   	for(i=0;i<20;i++){

   	   		given_sha1[i] = ((sha_calc_array[2*i] & 0x0000ffff ) << 4)+((sha_calc_array[(2*i)+1]) & 0x0000ffff) ;

   	   	}

   	   	for( i=0;i < clustercount_from_FAT;i++){
   	   		for( k=0; k< directory_entries_percluster; k++){

   	   			memcpy(&rootdir_Entrylist,&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((fileclusterarray[i]-2)*no_of_bytespersector*no_of_sectorspercluster)+(k*32)],32);

   	   			if(rootdir_Entrylist.DIR_Name[0]!=0x00){
   	   				if(rootdir_Entrylist.DIR_Name[0]==0xe5){
		   	   			sizeoffile = rootdir_Entrylist.DIR_FileSize;
		   	   			high2 = rootdir_Entrylist.DIR_FstClusHI ;
		   	   			low2 = rootdir_Entrylist.DIR_FstClusLO ;
		   	   			startingcluster_file =  ( high2 << 16 )+ low2;

		   	   			for(n=0;n<8;n++){

		   	   				if(rootdir_Entrylist.DIR_Name[n]==spacechar[0]){
		   	   					break;
		   	   				}
		   	   				else{
		   	   					templistfilename[listfilenameindex]=rootdir_Entrylist.DIR_Name[n];
		   	   					listfilenameindex+=1;
		   	   				}
		   	   			}

		   	   			if(rootdir_Entrylist.DIR_Name[8]!=spacechar[0]){
								templistfilename[listfilenameindex]=dotchar[0];
		   	   				listfilenameindex+=1;		  
		 	   				}

		   	   			for(n=8;n<11;n++){

		   	   				if(rootdir_Entrylist.DIR_Name[n]==spacechar[0]){
		   	   					break;
		   	   				}
		   	   				else{
		   	   					templistfilename[listfilenameindex]=rootdir_Entrylist.DIR_Name[n];
		   	   					listfilenameindex+=1;
		   	   				}
		   	   			}

		   	   			filelistname = (unsigned char*)calloc(listfilenameindex,sizeof(unsigned char));

		   	   			for(n=0;n<listfilenameindex;n++){
		   	   				filelistname[n]=templistfilename[n];
		   	   			}

		   	   			if(rootdir_Entrylist.DIR_Attr != 16){
		   	   			

		   	   				if(lengthoffilename==listfilenameindex && strncmp(modifiedfilename,filelistname,lengthoffilename)==0){

		   	   						unsigned char list_file[sizeoffile+100];

		   	   						list_sha1 = (unsigned char*)calloc(20, sizeof(unsigned char));

		   	   						if(sizeoffile==0){

		   	   							for(w=0;w<40;w++){

									   	   		if(empty_sha1[w] == '0'){
									   	   			 sha_calc_array[w] = 0 ;
									   	   		}

									   	   		if(empty_sha1[w] == '1'){
									   	   			 sha_calc_array[w] = 1 ;
									   	   		}

									   	   		if(empty_sha1[w] == '2'){
									   	   			 sha_calc_array[w] = 2 ;
									   	   		}

									   	   		if(empty_sha1[w] == '3'){
									   	   			 sha_calc_array[w] = 3 ;
									   	   		}
									   	   		if(empty_sha1[w] == '4'){
									   	   			 sha_calc_array[w] = 4 ;
									   	   		}
									   	   		if(empty_sha1[w] == '5'){
									   	   			 sha_calc_array[w] = 5 ;
									   	   		}
									   	   		if(empty_sha1[w] == '6'){
									   	   			 sha_calc_array[w] = 6 ;
									   	   		}
									   	   		if(empty_sha1[w] == '7'){
									   	   			 sha_calc_array[w] = 7 ;
									   	   		}
									   	   		if(empty_sha1[w] == '8'){
									   	   			 sha_calc_array[w] = 8 ;
									   	   		}
									   	   		if(empty_sha1[w] == '9'){
									   	   			 sha_calc_array[w] = 9 ;
									   	   		}
									   	   		if(empty_sha1[w] == 'a'){
									   	   			 sha_calc_array[w] = 10 ;
									   	   		}
									   	   		if(empty_sha1[w] == 'b'){
									   	   			 sha_calc_array[w] = 11 ;
									   	   		}
									   	   		if(empty_sha1[w] == 'c'){
									   	   			 sha_calc_array[w] = 12 ;
									   	   		}
									   	   		if(empty_sha1[w] == 'd'){
									   	   			 sha_calc_array[w] = 13 ;
									   	   		}
									   	   		if(empty_sha1[w] == 'e'){
									   	   			 sha_calc_array[w] = 14 ;
									   	   		}
									   	   		if(empty_sha1[w] == 'f'){
									   	   			 sha_calc_array[w] = 15 ;
									   	   		}

									   	   	}

		   	   							for(w=0;w<20;w++){
									   	   		list_sha1[w] = (sha_calc_array[2*w] << 4)+(sha_calc_array[(2*w)+1]) ;

									   	   	}
		   	   						}

		   	   						if(sizeoffile>0){
		   	   						
		   	   						sha_sizeoffile = sizeoffile;

		   	   						unsigned int clusterlist[9];
		   	   						unsigned int  fat_sha_milestone8[10]; 
		   	   						unsigned int a,b,c,d,e,f,g,h,o,u,t,s,q,y;
		   	   						b=0;

		   	   						for(a=2;a<12;a++){
		   	   							if( a == startingcluster_file){

		   	   							}

		   	   							else{
		   	   								clusterlist[b]=a;
		   	   								b++;
		   	   							}
		   	   						}

		   	   						
		   	   						size_t lastcluster_size;

		   	   						if((sizeoffile%cluster_size_bytes) ==0){
		   	   							lastcluster_size = cluster_size_bytes;		   	   						
		   	   						}
		   	   						else{
		   	   							lastcluster_size = (sizeoffile%cluster_size_bytes);
		   	   						}

		   	   						unsigned int no_clusters_required;

		   	   						if((sizeoffile%cluster_size_bytes) ==0){
		   	   							no_clusters_required = (sizeoffile/cluster_size_bytes);		   	   						
		   	   						}
		   	   						else{
		   	   							no_clusters_required = (sizeoffile/cluster_size_bytes)+1 ;
		   	   						}

		   	   						unsigned int no_extra_clusters_required = no_clusters_required -1; // Startingcluster is always included;


		   	   						if(no_extra_clusters_required > 0){
		   	   						
			   	   						for(a=0;a<9;a++){

			   	   							if(no_extra_clusters_required>1){

			   	   								for(b=0;b<9;b++){
			   	   									if(a!=b){
			   	   										if(no_extra_clusters_required>2){

			   	   											for(c=0;c<9;c++){
			   	   												if(b!=c){
			   	   													if(no_extra_clusters_required>3){

			   	   														for(d=0;d<9;d++){
			   	   															if(c!=d){

			   	   																if(no_extra_clusters_required>4){
			   	   																	for(e=0;e<9;e++){
			   	   																		if(d!=e){
			   	   																			if(no_extra_clusters_required>5){
			   	   																				for(f=0;f<9;f++){
			   	   																					if(e!=f){
			   	   																						if(no_extra_clusters_required>6){
			   	   																							for(g=0;g<9;g++){
			   	   																								if(f!=g){
			   	   																									if(no_extra_clusters_required>7){
			   	   																										for(h=0;h<9;h++){
			   	   																											if(g!=h){
			   	   																												if(no_extra_clusters_required>8){
			   	   																													for(o=0;o<9;o++){
			   	   																														if(h!=0){
																		   	   																	memcpy(&list_file,&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((startingcluster_file-2)*no_of_bytespersector*no_of_sectorspercluster)],cluster_size_bytes);	
																												   	   							memcpy(&list_file[1*cluster_size_bytes],&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((clusterlist[a]-2)*no_of_bytespersector*no_of_sectorspercluster)],cluster_size_bytes);		   	   					 			   	   										   	   					 			   	   									
																												   	   							memcpy(&list_file[2*cluster_size_bytes],&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((clusterlist[b]-2)*no_of_bytespersector*no_of_sectorspercluster)],cluster_size_bytes);	
																												   	   							memcpy(&list_file[3*cluster_size_bytes],&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((clusterlist[c]-2)*no_of_bytespersector*no_of_sectorspercluster)],cluster_size_bytes);		   	   					 			   	   										   	   					 			   	   																						   	   								   	   					 			   	   										   	   					 			   	   									
																												   	   							memcpy(&list_file[4*cluster_size_bytes],&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((clusterlist[d]-2)*no_of_bytespersector*no_of_sectorspercluster)],cluster_size_bytes);		   	   					 			   	   										   	   					 			   	   																						   	   								   	   					 			   	   										   	   					 			   	   									
																												   	   							memcpy(&list_file[5*cluster_size_bytes],&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((clusterlist[e]-2)*no_of_bytespersector*no_of_sectorspercluster)],cluster_size_bytes);		   	   					 			   	   										   	   					 			   	   																						   	   								   	   					 			   	   										   	   					 			   	   									
																												   	   							memcpy(&list_file[6*cluster_size_bytes],&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((clusterlist[f]-2)*no_of_bytespersector*no_of_sectorspercluster)],cluster_size_bytes);		   	   					 			   	   										   	   					 			   	   																						   	   								   	   					 			   	   										   	   					 			   	   									
																												   	   							memcpy(&list_file[7*cluster_size_bytes],&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((clusterlist[g]-2)*no_of_bytespersector*no_of_sectorspercluster)],cluster_size_bytes);		   	   					 			   	   										   	   					 			   	   																						   	   								   	   					 			   	   										   	   					 			   	   									
																												   	   							memcpy(&list_file[8*cluster_size_bytes],&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((clusterlist[h]-2)*no_of_bytespersector*no_of_sectorspercluster)],cluster_size_bytes);		   	   					 			   	   										   	   					 			   	   																						   	   								   	   					 			   	   										   	   					 			   	   									
																												   	   							memcpy(&list_file[9*cluster_size_bytes],&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((clusterlist[o]-2)*no_of_bytespersector*no_of_sectorspercluster)],lastcluster_size);		   	   					 
																											   	   								SHA1(list_file, sha_sizeoffile, list_sha1);

																													   	   						if(strncmp(list_sha1,given_sha1, 20)==0){	
																																   	   					matchingfilecount+=1;
																																   	   					size_matchedfile = sizeoffile;
																																   	   					startingcluster_matchedfile = startingcluster_file;
																																   	   					firstcharaddress = (no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((fileclusterarray[i]-2)*no_of_bytespersector*no_of_sectorspercluster)+(k*32);
																																   	   					for(y=0;y<no_of_fats;y++){
																														   	   								fat_table[y][startingcluster_file] = clusterlist[a];
																														   	   								fat_table[y][clusterlist[a]] = clusterlist[b];
																														   	   								fat_table[y][clusterlist[b]] = clusterlist[c];	
																														   	   								fat_table[y][clusterlist[c]] = clusterlist[d];	
																														   	   								fat_table[y][clusterlist[d]] = clusterlist[e];	
																														   	   								fat_table[y][clusterlist[e]] = clusterlist[f];
																														   	   								fat_table[y][clusterlist[f]] = clusterlist[g];
																														   	   								fat_table[y][clusterlist[g]] = clusterlist[h];
																														   	   								fat_table[y][clusterlist[h]] = clusterlist[o];									   	   																		   	   								
																														   	   								fat_table[y][clusterlist[o]] = 0x0ffffff9;
																														   	   							}
																																   	   					goto jump;			   	   																										
												   	   																							}			  			   	   																															
						   	   																											}
			   	   																													}

			   	   																												}
			   	   																												else{
															   	   																	memcpy(&list_file,&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((startingcluster_file-2)*no_of_bytespersector*no_of_sectorspercluster)],cluster_size_bytes);	
																									   	   							memcpy(&list_file[1*cluster_size_bytes],&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((clusterlist[a]-2)*no_of_bytespersector*no_of_sectorspercluster)],cluster_size_bytes);		   	   					 			   	   										   	   					 			   	   									
																									   	   							memcpy(&list_file[2*cluster_size_bytes],&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((clusterlist[b]-2)*no_of_bytespersector*no_of_sectorspercluster)],cluster_size_bytes);	
																									   	   							memcpy(&list_file[3*cluster_size_bytes],&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((clusterlist[c]-2)*no_of_bytespersector*no_of_sectorspercluster)],cluster_size_bytes);		   	   					 			   	   										   	   					 			   	   																						   	   								   	   					 			   	   										   	   					 			   	   									
																									   	   							memcpy(&list_file[4*cluster_size_bytes],&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((clusterlist[d]-2)*no_of_bytespersector*no_of_sectorspercluster)],cluster_size_bytes);		   	   					 			   	   										   	   					 			   	   																						   	   								   	   					 			   	   										   	   					 			   	   									
																									   	   							memcpy(&list_file[5*cluster_size_bytes],&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((clusterlist[e]-2)*no_of_bytespersector*no_of_sectorspercluster)],cluster_size_bytes);		   	   					 			   	   										   	   					 			   	   																						   	   								   	   					 			   	   										   	   					 			   	   									
																									   	   							memcpy(&list_file[6*cluster_size_bytes],&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((clusterlist[f]-2)*no_of_bytespersector*no_of_sectorspercluster)],cluster_size_bytes);		   	   					 			   	   										   	   					 			   	   																						   	   								   	   					 			   	   										   	   					 			   	   									
																									   	   							memcpy(&list_file[7*cluster_size_bytes],&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((clusterlist[g]-2)*no_of_bytespersector*no_of_sectorspercluster)],cluster_size_bytes);		   	   					 			   	   										   	   					 			   	   																						   	   								   	   					 			   	   										   	   					 			   	   									
																									   	   							memcpy(&list_file[8*cluster_size_bytes],&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((clusterlist[h]-2)*no_of_bytespersector*no_of_sectorspercluster)],lastcluster_size);		   	   					 
																								   	   								SHA1(list_file, sha_sizeoffile, list_sha1);

																										   	   						if(strncmp(list_sha1,given_sha1, 20)==0){	
																													   	   					matchingfilecount+=1;
																													   	   					size_matchedfile = sizeoffile;
																													   	   					startingcluster_matchedfile = startingcluster_file;
																													   	   					firstcharaddress = (no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((fileclusterarray[i]-2)*no_of_bytespersector*no_of_sectorspercluster)+(k*32);
																													   	   					for(y=0;y<no_of_fats;y++){
																											   	   								fat_table[y][startingcluster_file] = clusterlist[a];
																											   	   								fat_table[y][clusterlist[a]] = clusterlist[b];
																											   	   								fat_table[y][clusterlist[b]] = clusterlist[c];	
																											   	   								fat_table[y][clusterlist[c]] = clusterlist[d];	
																											   	   								fat_table[y][clusterlist[d]] = clusterlist[e];	
																											   	   								fat_table[y][clusterlist[e]] = clusterlist[f];
																											   	   								fat_table[y][clusterlist[f]] = clusterlist[g];
																											   	   								fat_table[y][clusterlist[g]] = clusterlist[h];									   	   																		   	   								
																											   	   								fat_table[y][clusterlist[h]] = 0x0ffffff9;
																											   	   							}
																													   	   					goto jump;			   	   																										
									   	   																							}			   	   																													
			   	   																												}

			   	   																											}
			   	   																										}

			   	   																									}
			   	   																									else{
												   	   																	memcpy(&list_file,&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((startingcluster_file-2)*no_of_bytespersector*no_of_sectorspercluster)],cluster_size_bytes);	
																						   	   							memcpy(&list_file[1*cluster_size_bytes],&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((clusterlist[a]-2)*no_of_bytespersector*no_of_sectorspercluster)],cluster_size_bytes);		   	   					 			   	   										   	   					 			   	   									
																						   	   							memcpy(&list_file[2*cluster_size_bytes],&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((clusterlist[b]-2)*no_of_bytespersector*no_of_sectorspercluster)],cluster_size_bytes);	
																						   	   							memcpy(&list_file[3*cluster_size_bytes],&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((clusterlist[c]-2)*no_of_bytespersector*no_of_sectorspercluster)],cluster_size_bytes);		   	   					 			   	   										   	   					 			   	   																						   	   								   	   					 			   	   										   	   					 			   	   									
																						   	   							memcpy(&list_file[4*cluster_size_bytes],&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((clusterlist[d]-2)*no_of_bytespersector*no_of_sectorspercluster)],cluster_size_bytes);		   	   					 			   	   										   	   					 			   	   																						   	   								   	   					 			   	   										   	   					 			   	   									
																						   	   							memcpy(&list_file[5*cluster_size_bytes],&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((clusterlist[e]-2)*no_of_bytespersector*no_of_sectorspercluster)],cluster_size_bytes);		   	   					 			   	   										   	   					 			   	   																						   	   								   	   					 			   	   										   	   					 			   	   									
																						   	   							memcpy(&list_file[6*cluster_size_bytes],&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((clusterlist[f]-2)*no_of_bytespersector*no_of_sectorspercluster)],cluster_size_bytes);		   	   					 			   	   										   	   					 			   	   																						   	   								   	   					 			   	   										   	   					 			   	   									
																						   	   							memcpy(&list_file[7*cluster_size_bytes],&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((clusterlist[g]-2)*no_of_bytespersector*no_of_sectorspercluster)],lastcluster_size);		   	   					 
																					   	   								SHA1(list_file, sha_sizeoffile, list_sha1);

																							   	   						if(strncmp(list_sha1,given_sha1, 20)==0){	
																										   	   					matchingfilecount+=1;
																										   	   					size_matchedfile = sizeoffile;
																										   	   					startingcluster_matchedfile = startingcluster_file;
																										   	   					firstcharaddress = (no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((fileclusterarray[i]-2)*no_of_bytespersector*no_of_sectorspercluster)+(k*32);
																										   	   					for(y=0;y<no_of_fats;y++){
																								   	   								fat_table[y][startingcluster_file] = clusterlist[a];
																								   	   								fat_table[y][clusterlist[a]] = clusterlist[b];
																								   	   								fat_table[y][clusterlist[b]] = clusterlist[c];	
																								   	   								fat_table[y][clusterlist[c]] = clusterlist[d];	
																								   	   								fat_table[y][clusterlist[d]] = clusterlist[e];	
																								   	   								fat_table[y][clusterlist[e]] = clusterlist[f];
																								   	   								fat_table[y][clusterlist[f]] = clusterlist[g];									   	   																		   	   								
																								   	   								fat_table[y][clusterlist[g]] = 0x0ffffff9;
																								   	   							}
																										   	   					goto jump;			   	   																										
						   	   																							}
			   	   																								}

			   	   																							}

			   	   																						}
			   	   																					}
			   	   																						else{
									   	   																	memcpy(&list_file,&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((startingcluster_file-2)*no_of_bytespersector*no_of_sectorspercluster)],cluster_size_bytes);	
																			   	   							memcpy(&list_file[1*cluster_size_bytes],&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((clusterlist[a]-2)*no_of_bytespersector*no_of_sectorspercluster)],cluster_size_bytes);		   	   					 			   	   										   	   					 			   	   									
																			   	   							memcpy(&list_file[2*cluster_size_bytes],&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((clusterlist[b]-2)*no_of_bytespersector*no_of_sectorspercluster)],cluster_size_bytes);	
																			   	   							memcpy(&list_file[3*cluster_size_bytes],&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((clusterlist[c]-2)*no_of_bytespersector*no_of_sectorspercluster)],cluster_size_bytes);		   	   					 			   	   										   	   					 			   	   																						   	   								   	   					 			   	   										   	   					 			   	   									
																			   	   							memcpy(&list_file[4*cluster_size_bytes],&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((clusterlist[d]-2)*no_of_bytespersector*no_of_sectorspercluster)],cluster_size_bytes);		   	   					 			   	   										   	   					 			   	   																						   	   								   	   					 			   	   										   	   					 			   	   									
																			   	   							memcpy(&list_file[5*cluster_size_bytes],&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((clusterlist[e]-2)*no_of_bytespersector*no_of_sectorspercluster)],cluster_size_bytes);		   	   					 			   	   										   	   					 			   	   																						   	   								   	   					 			   	   										   	   					 			   	   									
																			   	   							memcpy(&list_file[6*cluster_size_bytes],&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((clusterlist[f]-2)*no_of_bytespersector*no_of_sectorspercluster)],lastcluster_size);		   	   					 
																		   	   								SHA1(list_file, sha_sizeoffile, list_sha1);

																				   	   						if(strncmp(list_sha1,given_sha1, 20)==0){	
																							   	   					matchingfilecount+=1;
																							   	   					size_matchedfile = sizeoffile;
																							   	   					startingcluster_matchedfile = startingcluster_file;
																							   	   					firstcharaddress = (no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((fileclusterarray[i]-2)*no_of_bytespersector*no_of_sectorspercluster)+(k*32);
																							   	   					for(y=0;y<no_of_fats;y++){
																					   	   								fat_table[y][startingcluster_file] = clusterlist[a];
																					   	   								fat_table[y][clusterlist[a]] = clusterlist[b];
																					   	   								fat_table[y][clusterlist[b]] = clusterlist[c];	
																					   	   								fat_table[y][clusterlist[c]] = clusterlist[d];	
																					   	   								fat_table[y][clusterlist[d]] = clusterlist[e];	
																					   	   								fat_table[y][clusterlist[e]] = clusterlist[f];									   	   																		   	   								
																					   	   								fat_table[y][clusterlist[f]] = 0x0ffffff9;
																					   	   							}
																							   	   					goto jump;
																							   	   			}			   	   																							
			   	   																						}
			   	   																					}
			   	   																				}

			   	   																			}

			   	   																			else{
						   	   																	memcpy(&list_file,&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((startingcluster_file-2)*no_of_bytespersector*no_of_sectorspercluster)],cluster_size_bytes);	
																   	   							memcpy(&list_file[1*cluster_size_bytes],&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((clusterlist[a]-2)*no_of_bytespersector*no_of_sectorspercluster)],cluster_size_bytes);		   	   					 			   	   										   	   					 			   	   									
																   	   							memcpy(&list_file[2*cluster_size_bytes],&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((clusterlist[b]-2)*no_of_bytespersector*no_of_sectorspercluster)],cluster_size_bytes);	
																   	   							memcpy(&list_file[3*cluster_size_bytes],&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((clusterlist[c]-2)*no_of_bytespersector*no_of_sectorspercluster)],cluster_size_bytes);		   	   					 			   	   										   	   					 			   	   																						   	   								   	   					 			   	   										   	   					 			   	   									
																   	   							memcpy(&list_file[4*cluster_size_bytes],&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((clusterlist[d]-2)*no_of_bytespersector*no_of_sectorspercluster)],cluster_size_bytes);		   	   					 			   	   										   	   					 			   	   																						   	   								   	   					 			   	   										   	   					 			   	   									
																   	   							memcpy(&list_file[5*cluster_size_bytes],&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((clusterlist[e]-2)*no_of_bytespersector*no_of_sectorspercluster)],lastcluster_size);		   	   					 
															   	   								SHA1(list_file, sha_sizeoffile, list_sha1);

																	   	   						if(strncmp(list_sha1,given_sha1, 20)==0){	
																				   	   					matchingfilecount+=1;
																				   	   					size_matchedfile = sizeoffile;
																				   	   					startingcluster_matchedfile = startingcluster_file;
																				   	   					firstcharaddress = (no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((fileclusterarray[i]-2)*no_of_bytespersector*no_of_sectorspercluster)+(k*32);
																				   	   					for(y=0;y<no_of_fats;y++){
																		   	   								fat_table[y][startingcluster_file] = clusterlist[a];
																		   	   								fat_table[y][clusterlist[a]] = clusterlist[b];
																		   	   								fat_table[y][clusterlist[b]] = clusterlist[c];	
																		   	   								fat_table[y][clusterlist[c]] = clusterlist[d];	
																		   	   								fat_table[y][clusterlist[d]] = clusterlist[e];										   	   																		   	   								
																		   	   								fat_table[y][clusterlist[e]] = 0x0ffffff9;
																		   	   							}
																				   	   					goto jump;
																				   	   			}
			   	   																			}
			   	   																		}
			   	   																	}

			   	   																}

			   	   																else{
			   	   																	memcpy(&list_file,&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((startingcluster_file-2)*no_of_bytespersector*no_of_sectorspercluster)],cluster_size_bytes);	
													   	   							memcpy(&list_file[1*cluster_size_bytes],&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((clusterlist[a]-2)*no_of_bytespersector*no_of_sectorspercluster)],cluster_size_bytes);		   	   					 			   	   										   	   					 			   	   									
													   	   							memcpy(&list_file[2*cluster_size_bytes],&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((clusterlist[b]-2)*no_of_bytespersector*no_of_sectorspercluster)],cluster_size_bytes);	
													   	   							memcpy(&list_file[3*cluster_size_bytes],&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((clusterlist[c]-2)*no_of_bytespersector*no_of_sectorspercluster)],cluster_size_bytes);		   	   					 			   	   										   	   					 			   	   																						   	   								   	   					 			   	   										   	   					 			   	   									
													   	   							memcpy(&list_file[4*cluster_size_bytes],&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((clusterlist[d]-2)*no_of_bytespersector*no_of_sectorspercluster)],lastcluster_size);		   	   					 
												   	   								SHA1(list_file, sha_sizeoffile, list_sha1);

														   	   						if(strncmp(list_sha1,given_sha1, 20)==0){	
																	   	   					matchingfilecount+=1;
																	   	   					size_matchedfile = sizeoffile;
																	   	   					startingcluster_matchedfile = startingcluster_file;
																	   	   					firstcharaddress = (no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((fileclusterarray[i]-2)*no_of_bytespersector*no_of_sectorspercluster)+(k*32);
																	   	   					for(y=0;y<no_of_fats;y++){
															   	   								fat_table[y][startingcluster_file] = clusterlist[a];
															   	   								fat_table[y][clusterlist[a]] = clusterlist[b];
															   	   								fat_table[y][clusterlist[b]] = clusterlist[c];	
															   	   								fat_table[y][clusterlist[c]] = clusterlist[d];											   	   																		   	   								
															   	   								fat_table[y][clusterlist[d]] = 0x0ffffff9;
															   	   							}
																	   	   					goto jump;
																	   	   			}
			   	   																}
			   	   															}
			   	   														}
			   	   													}

			   	   													else{
			   	   														memcpy(&list_file,&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((startingcluster_file-2)*no_of_bytespersector*no_of_sectorspercluster)],cluster_size_bytes);	
										   	   							memcpy(&list_file[1*cluster_size_bytes],&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((clusterlist[a]-2)*no_of_bytespersector*no_of_sectorspercluster)],cluster_size_bytes);		   	   					 			   	   										   	   					 			   	   									
										   	   							memcpy(&list_file[2*cluster_size_bytes],&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((clusterlist[b]-2)*no_of_bytespersector*no_of_sectorspercluster)],cluster_size_bytes);		   	   					 			   	   										   	   					 			   	   									
										   	   							memcpy(&list_file[3*cluster_size_bytes],&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((clusterlist[c]-2)*no_of_bytespersector*no_of_sectorspercluster)],lastcluster_size);		   	   					 
									   	   								SHA1(list_file, sha_sizeoffile, list_sha1);

											   	   						if(strncmp(list_sha1,given_sha1, 20)==0){	
														   	   					matchingfilecount+=1;
														   	   					size_matchedfile = sizeoffile;
														   	   					startingcluster_matchedfile = startingcluster_file;
														   	   					firstcharaddress = (no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((fileclusterarray[i]-2)*no_of_bytespersector*no_of_sectorspercluster)+(k*32);
														   	   					for(y=0;y<no_of_fats;y++){
												   	   								fat_table[y][startingcluster_file] = clusterlist[a];
												   	   								fat_table[y][clusterlist[a]] = clusterlist[b];
												   	   								fat_table[y][clusterlist[b]] = clusterlist[c];												   	   																		   	   								
												   	   								fat_table[y][clusterlist[c]] = 0x0ffffff9;
												   	   							}
														   	   					goto jump;
														   	   			}
			   	   													}
			   	   												}
			   	   											}
			   	   										}

			   	   										else {
								   	   							memcpy(&list_file,&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((startingcluster_file-2)*no_of_bytespersector*no_of_sectorspercluster)],cluster_size_bytes);	
								   	   							memcpy(&list_file[1*cluster_size_bytes],&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((clusterlist[a]-2)*no_of_bytespersector*no_of_sectorspercluster)],cluster_size_bytes);		   	   					 			   	   										   	   					 			   	   									
								   	   							memcpy(&list_file[2*cluster_size_bytes],&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((clusterlist[b]-2)*no_of_bytespersector*no_of_sectorspercluster)],lastcluster_size);		   	   					 
							   	   								SHA1(list_file, sha_sizeoffile, list_sha1);

									   	   						if(strncmp(list_sha1,given_sha1, 20)==0){	
												   	   					matchingfilecount+=1;
												   	   					size_matchedfile = sizeoffile;
												   	   					startingcluster_matchedfile = startingcluster_file;
												   	   					firstcharaddress = (no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((fileclusterarray[i]-2)*no_of_bytespersector*no_of_sectorspercluster)+(k*32);
												   	   					for(y=0;y<no_of_fats;y++){
										   	   								fat_table[y][startingcluster_file] = clusterlist[a];
										   	   								fat_table[y][clusterlist[a]] = clusterlist[b];										   	   								
										   	   								fat_table[y][clusterlist[b]] = 0x0ffffff9;
										   	   							}
												   	   					goto jump;

			   	   												}
			   	   										}
			   	   									}
			   	   								}
			   	   							}
			   	   							else{
					   	   							memcpy(&list_file,&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((startingcluster_file-2)*no_of_bytespersector*no_of_sectorspercluster)],cluster_size_bytes);		   	   					 			   	   									
					   	   							memcpy(&list_file[1*cluster_size_bytes],&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((clusterlist[a]-2)*no_of_bytespersector*no_of_sectorspercluster)],lastcluster_size);		   	   					 
				   	   								SHA1(list_file, sha_sizeoffile, list_sha1);

						   	   						if(strncmp(list_sha1,given_sha1, 20)==0){	
									   	   					matchingfilecount+=1;
									   	   					size_matchedfile = sizeoffile;
									   	   					startingcluster_matchedfile = startingcluster_file;
									   	   					firstcharaddress = (no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((fileclusterarray[i]-2)*no_of_bytespersector*no_of_sectorspercluster)+(k*32);
									   	   					for(y=0;y<no_of_fats;y++){
							   	   								fat_table[y][startingcluster_file] = clusterlist[a];
							   	   								fat_table[y][clusterlist[a]] = 0x0ffffff9;
							   	   							}
									   	   					goto jump;

						   	   						}
			   	   							}

			   	   						}

		   	   						}

		   	   						else {

		   	   								memcpy(&list_file,&mappingoffile[(no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((startingcluster_file-2)*no_of_bytespersector*no_of_sectorspercluster)],sha_sizeoffile);		   	   					 
		   	   								SHA1(list_file, sha_sizeoffile, list_sha1);

				   	   						if(strncmp(list_sha1,given_sha1, 20)==0){	
							   	   					matchingfilecount+=1;
							   	   					size_matchedfile = sizeoffile;
							   	   					startingcluster_matchedfile = startingcluster_file;
							   	   					firstcharaddress = (no_of_reservedsectors*no_of_bytespersector)+(no_of_fats*fat_size_inbytes)+((fileclusterarray[i]-2)*no_of_bytespersector*no_of_sectorspercluster)+(k*32);
							   	   					for(y=0;y<no_of_fats;y++){
							   	   						fat_table[y][startingcluster_file] = 0x0ffffff9;
							   	   					}
							   	   					goto jump;
				   	   						}
		   	   						}
		   	   			}

		   	   					jump : 

		   	   					free(list_sha1);

		   	   					if(matchingfilecount>1){
		   	   						printf("%.*s: multiple candidates found\n",lengthoffilename,argv[filenameindex]);
		   	   						fflush(stdout);
		   	   						return 0;
		   	   					}
   								}


		   	   			}

		   	   			listfilenameindex=0;
		   	   			free(filelistname);
	   	   			
   	   				}
   	   			}

   	   			else{

   	   					if(matchingfilecount==0){
   	   						printf("%.*s: file not found\n",lengthoffilename,argv[filenameindex]);
   	   						fflush(stdout);
   	   						return 0;
   	   					}

   	   					unsigned int no_of_clusters_matchedfile;

   	   					if(size_matchedfile%(no_of_bytespersector*no_of_sectorspercluster) == 0){

   	   						no_of_clusters_matchedfile = size_matchedfile/(no_of_bytespersector*no_of_sectorspercluster);

   	   					}
   	   					else {

   	   						  	no_of_clusters_matchedfile = (size_matchedfile/(no_of_bytespersector*no_of_sectorspercluster)) + 1 ;
   	   					}

   	   						memcpy(&mappingoffile[firstcharaddress],&argv[filenameindex][0],1);

   	   					unsigned int x,y,z;

   	   					if(size_matchedfile==0){

   	   						printf("%.*s: successfully recovered with SHA-1\n",lengthoffilename,argv[filenameindex]);
   	   						return 0;

   	   					}

   	   						y = fat1_area_startingindex;

						    for(x=0;x<no_of_fats;x++){

						    	for(z=0;z<no_of_fat_entries;z++){

						    		memcpy(&mappingoffile[y],&fat_table[x][z],4);
						    		y = y + 4;
						    	}
						    }

   	   				printf("%.*s: successfully recovered with SHA-1\n",lengthoffilename,argv[filenameindex]);

   	   				return 0;
   	   			}

   	   		}
   	   	}

   	   	if(matchingfilecount==0){
   	   						printf("%.*s: file not found\n",lengthoffilename,argv[filenameindex]);
   	   						fflush(stdout);
   	   						return 0;
   	   					}

   	   					unsigned int no_of_clusters_matchedfile;

   	   					if(size_matchedfile%(no_of_bytespersector*no_of_sectorspercluster) == 0){

   	   						no_of_clusters_matchedfile = size_matchedfile/(no_of_bytespersector*no_of_sectorspercluster);
   	   					}
   	   					else {
   	   						  	no_of_clusters_matchedfile = (size_matchedfile/(no_of_bytespersector*no_of_sectorspercluster)) + 1 ;
   	   					}

   	   						memcpy(&mappingoffile[firstcharaddress],&argv[filenameindex][0],1);

   	   					unsigned int x,y,z;

   	   					if(size_matchedfile==0){

   	   						printf("%.*s: successfully recovered with SHA-1\n",lengthoffilename,argv[filenameindex]);
   	   						return 0;

   	   					}
   	   		
   	   						y = fat1_area_startingindex;

						    for(x=0;x<no_of_fats;x++){

						    	for(z=0;z<no_of_fat_entries;z++){

						    		memcpy(&mappingoffile[y],&fat_table[x][z],4);
						    		y = y + 4;
						    	}
						    }

   	   				printf("%.*s: successfully recovered with SHA-1\n",lengthoffilename,argv[filenameindex]);
   	   				return 0;

   }


}