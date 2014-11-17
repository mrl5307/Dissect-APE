/* This is the dissector for the custom APE protocol 
 *
 * This protocol has two elements: A size and a string
 *
 * The protocol is defined at github.com/rjwalls/ape-counter
 *
 * TODO : Make comments better
 */



/* Includes
 * --------
 * config.h      : 
 * epac/packet.h :
 *
 */
#include "config.h"
#include <epan/packet.h>
#include <glib.h>


/* Globals
 * -------
 *  APE_PORT : the port number this protocol will be read from
 *    TODO : Find out what port to set this to
 *
 */
#define APE_PORT 0000

/*ID of the APE protocol */
static int proto_ape = -1;

/*Handles of the subdissectors */
static dissector_handle_t data_handle = NULL;
static dissector_handle_t ape_handle;



static gint hf_ape_length = -1;
static gchar hf_ape_string = -1; 
static gint ett_ape = -1;





/* Function : dissect_ape
 * ----------------------
 *  Purpose : Called to dissect the packets presented to it.
 *  Inputs  : tvb   : buffer used to hold packet data
 *            pinfo : general data about the protocol
 *            tree  : where the dissection takes place
 *  Outputs : If the tree parameter is NULL, we only want 
 */
static void dissect_ape(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "APE");
  col_clear(pinfo->cinfo, COL_INFO);



  /* Get the packet length 
    TODO : Find out the difference between this and the stuff below*/
     guint8 packet_length = tvb_get_guint8(tvb, 0);
  

  /* Check if we want a summary of info or the actual protocol information 
   * If the tree pointer is NULL we only want a summary*/
  if(tree){
    gint offset = 0;

    proto_item *ti = NULL;
    proto_tree *ape_tree = NULL;
    
    ti = proto_tree_add_item(tree, proto_ape, tvb, 0, -1, ENC_NA);
    ape_tree = proto_item_add_subtree(ti, ett_ape);
    proto_tree_add_item(ape_tree, hf_ape_length, tvb, 0, 1, ENC_BIG_ENDIAN);
    offset += 1;


    /* proto_tree_add_item
     * 
     * Parameters :
     *  ape_tree       : tree to add to
     *  hf_ape_string  : label
     *  tvb            : using this as data
     *  offset         : starting place
     *  offset+packet  : ending place
     *  END_BIG_ENDIAN : big endian notation
     * 
     * TODO : make this comment better and check if this is right
     *
     *
     */
    proto_tree_add_item(ape_tree, hf_ape_string, tvb, offset, offset+packet_length, ENC_BIG_ENDIAN);
  }

}





/* Function : proto_register_ape
 * -----------------------------
 *  Purpose : Register the protocol and give it names.
 *  Inputs  : None
 *  Outputs : None
 */
void proto_register_ape(void){

  /*Define the elements we will be displaying*/
  static hf_register_info hf[] = {
    
    
    /* This should be the string held in the packets payload.
     * APE_Length : Field Name
     * ape.length : Field Name abbreviation
     * FT_UINT8   : Type of data
     * BASE_DEC   : Display type
     * NULL       : Strings : TODO : find out what this means
     * 0x0        : Bitmark 
     * Payload length : Blurb 
     * HFILL      : Always HFILL
     */
    { &hf_ape_length,
      { "APE Length", "ape.length", 
        FT_UINT8, BASE_DEC,
        NULL, 0x0, 
        "Payload Length", HFILL 
      }
    },


    /* This should be the string held in the packets payload.
     * APE_String : Field Name
     * ape.string : Field Name abbreviation
     * FT_STRING  : Type of data
     * STR_ASCII  : Display type
     * NULL       : Strings : TODO : find out what this means
     * 0x0        : Bitmark 
     * Payload    : Blurb 
     * HFILL      : Always HFILL
     */
    { &hf_ape_string, 
      { "APE String", "ape.string", 
        FT_STRING, STR_ASCII,
        NULL, 0x0, 
        "Payload", HFILL 
      }
    }
  };


  /*Set up protocol subtree array 
   * TODO: Find out what this does*/
  static gint *ett[] = {
    &ett_ape
  };


  proto_ape = proto_register_protocol(
    "APE Protocol", /* name */
    "APE", /* short name    */
    "ape"  /* abbreviation  */
    );

  /*Register the array and the subtree array  */
  proto_register_field_array(proto_ape, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));


}


/* Function : proto_reg_handoff_ape
 * --------------------------------
 *  Purpose : Initialise the dissector and stuff.
 *  Inputs  : None
 *  Outputs : None
 */
void proto_reg_handoff_ape(void){

  /* Create a dissector handle */
  static dissector_handle_t ape_handle;

  /*   */
  ape_handle = create_dissector_handle(dissect_ape, proto_ape);

  /*Can change udp port to tcp.port depending on what type we want*/
  dissector_add_uint("udp.port", APE_PORT, ape_handle);
}













































