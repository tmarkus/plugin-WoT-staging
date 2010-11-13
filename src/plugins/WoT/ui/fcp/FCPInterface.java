/* This code is part of WoT, a plugin for Freenet. It is distributed 
 * under the GNU General Public License, version 2 (or at your option
 * any later version). See http://www.gnu.org/ for details of the GPL. */
package plugins.WoT.ui.fcp;

import java.io.IOException;
import java.net.MalformedURLException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Iterator;
import java.util.List;
import java.util.Map.Entry;

import plugins.WoT.Identity;
import plugins.WoT.OwnIdentity;
import plugins.WoT.Score;
import plugins.WoT.Trust;
import plugins.WoT.WoT;
import plugins.WoT.exceptions.InvalidParameterException;
import plugins.WoT.exceptions.NoSuchContextException;
import plugins.WoT.exceptions.NotInTrustTreeException;
import plugins.WoT.exceptions.NotTrustedException;
import plugins.WoT.exceptions.UnknownIdentityException;
import plugins.WoT.exceptions.UnknownPuzzleException;
import plugins.WoT.introduction.IntroductionPuzzle;
import plugins.WoT.introduction.IntroductionPuzzle.PuzzleType;
import plugins.WoT.introduction.IntroductionServer;

import com.db4o.ObjectSet;

import freenet.node.FSParseException;
import freenet.pluginmanager.FredPluginFCP;
import freenet.pluginmanager.PluginNotFoundException;
import freenet.pluginmanager.PluginReplySender;
import freenet.support.Base64;
import freenet.support.Logger;
import freenet.support.SimpleFieldSet;
import freenet.support.api.Bucket;

/**
 * @author xor (xor@freenetproject.org), Julien Cornuwel (batosai@freenetproject.org)
 */
public final class FCPInterface implements FredPluginFCP {

    private final WoT mWoT;

    public FCPInterface(final WoT myWoT) {
        mWoT = myWoT;
    }

    public void handle(final PluginReplySender replysender, final SimpleFieldSet params, final Bucket data, final int accesstype) {

        try {
            final String message = params.get("Message");
            
            if (message.equals("CreateIdentity")) {
                replysender.send(handleCreateIdentity(params), data);
            } else if (message.equals("SetTrust")) {
                replysender.send(handleSetTrust(params), data);
            } else if (message.equals("AddIdentity")) {
                replysender.send(handleAddIdentity(params), data);
            } else if (message.equals("GetIdentity")) {
                replysender.send(handleGetIdentity(params), data);
            } else if (message.equals("GetOwnIdentities")) {
                replysender.send(handleGetOwnIdentities(params), data);
            } else if (message.equals("GetIdentitiesByScore")) {
                replysender.send(handleGetIdentitiesByScore(params), data);
            } else if (message.equals("GetTrusters")) {
                replysender.send(handleGetTrusters(params), data);
            } else if (message.equals("GetTrustersCount")) {
            	replysender.send(handleGetTrustersCount(params), data);
            } else if (message.equals("GetTrustees")) {
                replysender.send(handleGetTrustees(params), data);
            } else if (message.equals("GetTrusteesCount")) {
            	replysender.send(handleGetTrusteesCount(params), data);
            } else if (message.equals("AddContext")) {
                replysender.send(handleAddContext(params), data);
            } else if (message.equals("RemoveContext")) {
                replysender.send(handleRemoveContext(params), data);
            } else if (message.equals("SetProperty")) {
                replysender.send(handleSetProperty(params), data);
            } else if (message.equals("GetProperty")) {
                replysender.send(handleGetProperty(params), data);
            } else if (message.equals("RemoveProperty")) {
                replysender.send(handleRemoveProperty(params), data);
            } else if (message.equals("GetIntroductionPuzzles")) {
            	replysender.send(handleGetIntroductionPuzzles(params), data);
            } else if (message.equals("GetIntroductionPuzzle")) {
            	replysender.send(handleGetIntroductionPuzzle(params), data);
            } else if (message.equals("SolveIntroductionPuzzle")) {
            	replysender.send(handleSolveIntroductionPuzzle(params), data);
            } else if (message.equals("Ping")) {
            	replysender.send(handlePing(), data);
            } else {
                throw new Exception("Unknown message (" + message + ")");
            }
        } catch (final Exception e) {
        	// TODO: This might miss some stuff which are errors. Find a better way of detecting which exceptions are okay.
        	boolean dontLog = e instanceof NoSuchContextException ||
        						e instanceof NotInTrustTreeException ||
        						e instanceof NotTrustedException ||
        						e instanceof UnknownIdentityException ||
        						e instanceof UnknownPuzzleException;
        	
        	if(!dontLog)
        		Logger.error(this, "FCP error", e);
        	
            try {
                replysender.send(errorMessageFCP(params.get("Message"), e), data);
            } catch (final PluginNotFoundException e1) {
                Logger.normal(this, "Connection to request sender lost", e1);
            }
        }
    }
    
    private String getMandatoryParameter(final SimpleFieldSet sfs, final String name) throws InvalidParameterException {
    	final String result = sfs.get(name);
    	if(result == null)
    		throw new IllegalArgumentException("Missing mandatory parameter: " + name);
    	
    	return result;
    }

    private SimpleFieldSet handleCreateIdentity(final SimpleFieldSet params)
    	throws InvalidParameterException, FSParseException, NoSuchAlgorithmException, InvalidKeySpecException, IOException {
    	
    	OwnIdentity identity;
    	
    	final String identityNickname = getMandatoryParameter(params, "Nickname");
    	final String identityContext = getMandatoryParameter(params, "Context");
    	final String identityPublishesTrustListStr = getMandatoryParameter(params, "PublishTrustList");
    	
    	final boolean identityPublishesTrustList = identityPublishesTrustListStr.equals("true") || identityPublishesTrustListStr.equals("yes");
    	final String identityRequestURI = params.get("RequestURI");
    	final String identityInsertURI = params.get("InsertURI");

    	/* The constructor will throw for us if one is missing. Do not use "||" because that would lead to creation of a new URI if the
    	 * user forgot one of the URIs and the user would not get notified about that.  */
    	synchronized(mWoT) { /* Preserve the locking order to prevent future deadlocks */
        if (identityRequestURI == null && identityInsertURI == null) {
            identity = mWoT.createOwnIdentity(identityNickname, identityPublishesTrustList, identityContext);
        } else {
            //FIXME: Add support for RSA keys in FCP
        	
        	identity = mWoT.createOwnIdentity(identityInsertURI, identityRequestURI, identityNickname, identityPublishesTrustList,
            		identityContext, "", "");
        }
   
        if (params.getBoolean("PublishIntroductionPuzzles", false))
        {
        	if(!identityPublishesTrustList)
        		throw new InvalidParameterException("An identity cannot publish introduction puzzles if it does not publish its trust list.");

        	synchronized(identity) {
	            // TODO: Create a function for those? 
        		try {
		            identity.addContext(IntroductionPuzzle.INTRODUCTION_CONTEXT);
		            identity.setProperty(IntroductionServer.PUZZLE_COUNT_PROPERTY, Integer.toString(IntroductionServer.DEFAULT_PUZZLE_COUNT));
		            mWoT.storeAndCommit(identity);
        		}
        		catch(RuntimeException e) {
        			mWoT.deleteIdentity(identity);
        			throw e;
        		}
        	}
        }
    	}

    	final SimpleFieldSet sfs = new SimpleFieldSet(true);
        sfs.putOverwrite("Message", "IdentityCreated");
        sfs.putOverwrite("ID", identity.getID());
        sfs.putOverwrite("InsertURI", identity.getInsertURI().toString());
        sfs.putOverwrite("RequestURI", identity.getRequestURI().toString());
        return sfs;
    }

    private SimpleFieldSet handleSetTrust(final SimpleFieldSet params)
    	throws InvalidParameterException, NumberFormatException, UnknownIdentityException
    {
    	final String trusterID = getMandatoryParameter(params, "Truster");
    	final String trusteeID = getMandatoryParameter(params, "Trustee");
    	final String trustValue = getMandatoryParameter(params, "Value");
    	final String trustComment = getMandatoryParameter(params, "Comment");

    	mWoT.setTrust(trusterID, trusteeID, Byte.parseByte(trustValue), trustComment);

    	final SimpleFieldSet sfs = new SimpleFieldSet(true);
    	sfs.putOverwrite("Message", "TrustSet");
    	return sfs;
    }

    private SimpleFieldSet handleAddIdentity(final SimpleFieldSet params) throws InvalidParameterException, MalformedURLException {
    	final String requestURI = getMandatoryParameter(params, "RequestURI");

    	final Identity identity = mWoT.addIdentity(requestURI);

    	final SimpleFieldSet sfs = new SimpleFieldSet(true);
    	sfs.putOverwrite("Message", "IdentityAdded");
    	sfs.putOverwrite("ID", identity.getID());
    	sfs.putOverwrite("Nickname", identity.getNickname());
    	return sfs;
    }

    private SimpleFieldSet handleGetIdentity(final SimpleFieldSet params) throws InvalidParameterException, UnknownIdentityException {
    	final String treeOwnerID = getMandatoryParameter(params, "TreeOwner"); 
    	final String identityID = getMandatoryParameter(params, "Identity");

    	final SimpleFieldSet sfs = new SimpleFieldSet(true);
    	sfs.putOverwrite("Message", "Identity");
    	
    	synchronized(mWoT) {
    		final OwnIdentity treeOwner = mWoT.getOwnIdentityByID(treeOwnerID);
    		final Identity identity = mWoT.getIdentityByID(identityID);

    		sfs.putOverwrite("Nickname", identity.getNickname());
    		sfs.putOverwrite("RequestURI", identity.getRequestURI().toString());

    		try {
    			final Trust trust = mWoT.getTrust(treeOwner, identity);
    			sfs.putOverwrite("Trust", Byte.toString(trust.getValue()));
    		} catch (final NotTrustedException e1) {
    			sfs.putOverwrite("Trust", "null");
    		}

    		try {
    			final Score score = mWoT.getScore(treeOwner, identity);
    			sfs.putOverwrite("Score", Integer.toString(score.getScore()));
    			sfs.putOverwrite("Rank", Integer.toString(score.getRank()));
    		} catch (final NotInTrustTreeException e) {
    			sfs.putOverwrite("Score", "null");
    			sfs.putOverwrite("Rank", "null");
    		}

    		final Iterator<String> contexts = identity.getContexts().iterator();
    		for(int i = 0; contexts.hasNext(); ++i) {
    			sfs.putOverwrite("Context" + i, contexts.next());
    		}

			int propertiesCounter = 0;
			for (Entry<String, String> property : identity.getProperties().entrySet()) {
				sfs.putOverwrite("Property" + propertiesCounter + ".Name", property.getKey());
				sfs.putOverwrite("Property" + propertiesCounter++ + ".Value", property.getValue());
			}
    	}
    	
		return sfs;
	}

    private SimpleFieldSet handleGetOwnIdentities(final SimpleFieldSet params) {
        final SimpleFieldSet sfs = new SimpleFieldSet(true);
		sfs.putOverwrite("Message", "OwnIdentities");

		synchronized(mWoT) {
			final ObjectSet<OwnIdentity> result = mWoT.getAllOwnIdentities();
	
			for(int i = 0; result.hasNext(); ) {
				final OwnIdentity oid = result.next();

				sfs.putOverwrite("Identity" + i, oid.getID());
				sfs.putOverwrite("RequestURI" + i, oid.getRequestURI().toString());
				sfs.putOverwrite("InsertURI" + i, oid.getInsertURI().toString());
				sfs.putOverwrite("Nickname" + i, oid.getNickname());
				// TODO: Allow the client to select what data he wants

				int contextCounter = 0;
				for (String context : oid.getContexts()) {
					sfs.putOverwrite("Contexts" + i + ".Context" + contextCounter++, context);
				}

				int propertiesCounter = 0;
				for (Entry<String, String> property : oid.getProperties().entrySet()) {
					sfs.putOverwrite("Properties" + i + ".Property" + propertiesCounter + ".Name", property.getKey());
					sfs.putOverwrite("Properties" + i + ".Property" + propertiesCounter++ + ".Value", property.getValue());
				}
				
				//include the RSA private key for the OwnIdentity
				sfs.putOverwrite("Properties" + i + ".Property" + propertiesCounter + ".Name", "RSAPrivateKey");
				sfs.putOverwrite("Properties" + i + ".Property" + propertiesCounter++ + ".Value", oid.getRSAPrivateKey());
				
				// This is here so you do not forget to do it IN the "if()" if you add an if() around the put() statements to allow selection
				++i;
			}
		}

		return sfs;
    }

    private SimpleFieldSet handleGetIdentitiesByScore(final SimpleFieldSet params) throws InvalidParameterException, UnknownIdentityException {
    	final String treeOwnerID = params.get("TreeOwner");
        final String selection = getMandatoryParameter(params, "Selection");
        final String context = getMandatoryParameter(params, "Context");

		final String selectString = selection.trim();
		int select = 0; // TODO: decide about the default value
		
		if (selectString.equals("+")) select = 1;
		else if (selectString.equals("-")) select = -1;
		else if (selectString.equals("0")) select = 0;
		else throw new InvalidParameterException("Unhandled selection value (" + select + ")");

		final SimpleFieldSet sfs = new SimpleFieldSet(true);
		sfs.putOverwrite("Message", "Identities");
		
		synchronized(mWoT) {
			final OwnIdentity treeOwner = treeOwnerID != null ? mWoT.getOwnIdentityByID(treeOwnerID) : null;
			final ObjectSet<Score> result = mWoT.getIdentitiesByScore(treeOwner, select);
			final boolean getAll = context.equals("");
	
			for(int i = 0; result.hasNext(); ) {
				final Score score = result.next();

				if(getAll || score.getTarget().hasContext(context)) {
					final Identity identity = score.getTarget();
					sfs.putOverwrite("Identity" + i, identity.getID());
					sfs.putOverwrite("RequestURI" + i, identity.getRequestURI().toString());
					sfs.putOverwrite("Nickname" + i, identity.getNickname() != null ? identity.getNickname() : "");

					int contextCounter = 0;
					for (String identityContext: identity.getContexts()) {
						sfs.putOverwrite("Contexts" + i + ".Context" + contextCounter++, identityContext);
					}

					int propertiesCounter = 0;
					for (Entry<String, String> property : identity.getProperties().entrySet()) {
						sfs.putOverwrite("Properties" + i + ".Property" + propertiesCounter + ".Name", property.getKey());
						sfs.putOverwrite("Properties" + i + ".Property" + propertiesCounter++ + ".Value", property.getValue());
					}
					// TODO: Allow the client to select what data he wants
					++i;
				}
			}
		}
		
		return sfs;
    }

    private SimpleFieldSet handleGetTrusters(final SimpleFieldSet params) throws InvalidParameterException, UnknownIdentityException {
    	final String identityID = getMandatoryParameter(params, "Identity");
    	final String context = getMandatoryParameter(params, "Context");
    	
        final SimpleFieldSet sfs = new SimpleFieldSet(true);
        sfs.putOverwrite("Message", "Identities");
        
        final boolean getAll = context.equals("");
        
        synchronized(mWoT) {
        	final ObjectSet<Trust> receivedTrusts = mWoT.getReceivedTrusts(mWoT.getIdentityByID(identityID));

			for(int i = 0; receivedTrusts.hasNext(); ) {
				final Trust trust = receivedTrusts.next();

				if(getAll || trust.getTruster().hasContext(params.get("Context"))) {
					sfs.putOverwrite("Identity" + i, trust.getTruster().getID());
					sfs.putOverwrite("Nickname" + i, trust.getTruster().getNickname());
					sfs.putOverwrite("RequestURI" + i, trust.getTruster().getRequestURI().toString());
					sfs.putOverwrite("Value" + i, Byte.toString(trust.getValue()));
					sfs.putOverwrite("Comment" + i, trust.getComment());

					int contextCounter = 0;
					for (String identityContext: trust.getTruster().getContexts()) {
						sfs.putOverwrite("Contexts" + i + ".Context" + contextCounter++, identityContext);
					}

					int propertiesCounter = 0;
					for (Entry<String, String> property : trust.getTruster().getProperties().entrySet()) {
						sfs.putOverwrite("Properties" + i + ".Property" + propertiesCounter + ".Name", property.getKey());
						sfs.putOverwrite("Properties" + i + ".Property" + propertiesCounter++ + ".Value", property.getValue());
					}
					// TODO: Allow the client to select what data he wants
					++i;
				}
			}
        }
        
        return sfs;
    }
    
    private SimpleFieldSet handleGetTrustersCount(final SimpleFieldSet params) throws InvalidParameterException, UnknownIdentityException {
    	final String identityID = getMandatoryParameter(params, "Identity");
    	//final String context = getMandatoryParameter(params, "Context"); // TODO: Implement as soon as we have per-context trust

        String selection = params.get("Selection");
        final int result;
        
        if(selection != null) {
        	selection = selection.trim();
    		final int select;
    		
    		if (selection.equals("+")) select = 1;
    		else if (selection.equals("-")) select = -1;
    		else if (selection.equals("0")) select = 0;
    		else throw new InvalidParameterException("Unhandled selection value (" + selection + ")");
        	
    		synchronized(mWoT) {
        		result = mWoT.getReceivedTrusts(mWoT.getIdentityByID(identityID), select).size();
        	}
        } else {
        	synchronized(mWoT) {
        		result = mWoT.getReceivedTrusts(mWoT.getIdentityByID(identityID)).size();
        	}
        }
    	
        final SimpleFieldSet sfs = new SimpleFieldSet(true);
        sfs.putOverwrite("Message", "TrustersCount");
        sfs.put("Value", result);
        return sfs;
    }

    private SimpleFieldSet handleGetTrustees(final SimpleFieldSet params) throws InvalidParameterException, UnknownIdentityException {
    	final String identityID = getMandatoryParameter(params, "Identity");
    	final String context = getMandatoryParameter(params, "Context");

    	final SimpleFieldSet sfs = new SimpleFieldSet(true);
        sfs.putOverwrite("Message", "Identities");
        
        final boolean getAll = context.equals("");

        synchronized(mWoT) {
        	final ObjectSet<Trust> givenTrusts = mWoT.getGivenTrusts(mWoT.getIdentityByID(identityID));

        	for(int i = 0; givenTrusts.hasNext(); ) {
        		final Trust trust = givenTrusts.next();
        		final Identity trustee = trust.getTrustee();

				if(getAll || trustee.hasContext(params.get("Context"))) {
					sfs.putOverwrite("Identity" + i, trustee.getID());
					sfs.putOverwrite("Nickname" + i, trustee.getNickname());
					sfs.putOverwrite("RequestURI" + i, trustee.getRequestURI().toString());
					sfs.putOverwrite("Value" + i, Byte.toString(trust.getValue()));
					sfs.putOverwrite("Comment" + i, trust.getComment());

					int contextCounter = 0;
					for (String identityContext: trust.getTruster().getContexts()) {
						sfs.putOverwrite("Contexts" + i + ".Context" + contextCounter++, identityContext);
					}

					int propertiesCounter = 0;
					for (Entry<String, String> property : trust.getTruster().getProperties().entrySet()) {
						sfs.putOverwrite("Properties" + i + ".Property" + propertiesCounter + ".Name", property.getKey());
						sfs.putOverwrite("Properties" + i + ".Property" + propertiesCounter++ + ".Value", property.getValue());
					}
					// TODO: Allow the client to select what data he wants
					++i;
				}
        	}
        }
        
        return sfs;
    }
    
    private SimpleFieldSet handleGetTrusteesCount(final SimpleFieldSet params) throws InvalidParameterException, UnknownIdentityException {
    	final String identityID = getMandatoryParameter(params, "Identity");
    	//final String context = getMandatoryParameter(params, "Context"); // TODO: Implement as soon as we have per-context trust

        String selection = params.get("Selection");
        final int result;
        
        if(selection != null) {
        	selection = selection.trim();
    		final int select;
    		
    		if (selection.equals("+")) select = 1;
    		else if (selection.equals("-")) select = -1;
    		else if (selection.equals("0")) select = 0;
    		else throw new InvalidParameterException("Unhandled selection value (" + selection + ")");
        	
    		synchronized(mWoT) {
        		result = mWoT.getGivenTrusts(mWoT.getIdentityByID(identityID), select).size();
        	}
        } else {
        	synchronized(mWoT) {
        		result = mWoT.getGivenTrusts(mWoT.getIdentityByID(identityID)).size();
        	}
        }
    	
        final SimpleFieldSet sfs = new SimpleFieldSet(true);
        sfs.putOverwrite("Message", "TrusteesCount");
        sfs.put("Value", result);
        return sfs;
    }
    
    private SimpleFieldSet handleAddContext(final SimpleFieldSet params) throws InvalidParameterException, UnknownIdentityException {
    	final String identityID = getMandatoryParameter(params, "Identity");
    	final String context = getMandatoryParameter(params, "Context");

        mWoT.addContext(identityID, context);

        final SimpleFieldSet sfs = new SimpleFieldSet(true);
        sfs.putOverwrite("Message", "ContextAdded");
        return sfs;
    }

    private SimpleFieldSet handleRemoveContext(final SimpleFieldSet params) throws InvalidParameterException, UnknownIdentityException {
    	final String identityID = getMandatoryParameter(params, "Identity");
    	final String context = getMandatoryParameter(params, "Context");

        mWoT.removeContext(identityID, context);

        final SimpleFieldSet sfs = new SimpleFieldSet(true);
        sfs.putOverwrite("Message", "ContextRemoved");
        return sfs;
    }

    private SimpleFieldSet handleSetProperty(final SimpleFieldSet params) throws InvalidParameterException, UnknownIdentityException {
    	final String identityID = getMandatoryParameter(params, "Identity");
        final String propertyName = getMandatoryParameter(params, "Property");
        final String propertyValue = getMandatoryParameter(params, "Value");

        mWoT.setProperty(identityID, propertyName, propertyValue);

        final SimpleFieldSet sfs = new SimpleFieldSet(true);
        sfs.putOverwrite("Message", "PropertyAdded");
        return sfs;
    }

    private SimpleFieldSet handleGetProperty(final SimpleFieldSet params) throws InvalidParameterException, UnknownIdentityException {
    	final String identityID = getMandatoryParameter(params, "Identity");
        final String propertyName = getMandatoryParameter(params, "Property");

        final SimpleFieldSet sfs = new SimpleFieldSet(true);
        sfs.putOverwrite("Message", "PropertyValue");
        sfs.putOverwrite("Property", mWoT.getProperty(identityID, propertyName));
        return sfs;
    }

    private SimpleFieldSet handleRemoveProperty(final SimpleFieldSet params) throws InvalidParameterException, UnknownIdentityException {
    	final String identityID = getMandatoryParameter(params, "Identity");
        final String propertyName = getMandatoryParameter(params, "Property");

        mWoT.removeProperty(identityID, propertyName);

        final SimpleFieldSet sfs = new SimpleFieldSet(true);
        sfs.putOverwrite("Message", "PropertyRemoved");
        return sfs;
    }
    
    private SimpleFieldSet handleGetIntroductionPuzzles(final SimpleFieldSet params) throws InvalidParameterException, UnknownIdentityException {
    	final String identityID = getMandatoryParameter(params, "Identity");
    	final String type = getMandatoryParameter(params, "Type");
    	final int amount = Integer.valueOf(getMandatoryParameter(params, "Amount"));
    	
    	List<IntroductionPuzzle> puzzles = mWoT.getIntroductionClient().getPuzzles(mWoT.getOwnIdentityByID(identityID), PuzzleType.valueOf(type), amount);
    	
    	final SimpleFieldSet sfs = new SimpleFieldSet(true);  	
    	sfs.putOverwrite("Message", "IntroductionPuzzles");
    	
    	int index = 0;
    	
    	for(IntroductionPuzzle puzzle : puzzles) {
    		sfs.putOverwrite("Puzzle" + index, puzzle.getID());    		
    		++index;
    	}
    	
    	return sfs;
    }
    
    private SimpleFieldSet handleGetIntroductionPuzzle(final SimpleFieldSet params) throws InvalidParameterException, UnknownPuzzleException {
    	final String puzzleID = getMandatoryParameter(params, "Puzzle");
    	
    	IntroductionPuzzle puzzle = mWoT.getIntroductionPuzzleStore().getByID(puzzleID);
    	    	
    	final SimpleFieldSet result = new SimpleFieldSet(true);
    	result.putOverwrite("Message", "IntroductionPuzzle");
    	result.putOverwrite("Type", puzzle.getType().toString());
    	result.putOverwrite("MimeType", puzzle.getMimeType());
    	result.putOverwrite("Data", Base64.encodeStandard(puzzle.getData()));
    	return result;
    }
    
    private SimpleFieldSet handleSolveIntroductionPuzzle(final SimpleFieldSet params) throws InvalidParameterException, UnknownIdentityException, UnknownPuzzleException {
    	final String identityID = getMandatoryParameter(params, "Identity");
    	final String puzzleID = getMandatoryParameter(params, "Puzzle");
    	final String solution = getMandatoryParameter(params, "Solution");
    	
    	mWoT.getIntroductionClient().solvePuzzle(mWoT.getOwnIdentityByID(identityID), mWoT.getIntroductionPuzzleStore().getByID(puzzleID), solution);
    	
    	final SimpleFieldSet sfs = new SimpleFieldSet(true);
    	sfs.putOverwrite("Message", "PuzzleSolved");
    	return sfs;
    }
    
    private SimpleFieldSet handlePing() {
    	final SimpleFieldSet sfs = new SimpleFieldSet(true);
    	sfs.putOverwrite("Message", "Pong");
    	return sfs;
    }

    private SimpleFieldSet errorMessageFCP(final String originalMessage, final Exception e) {
        final SimpleFieldSet sfs = new SimpleFieldSet(true);
        sfs.putOverwrite("Message", "Error");
        sfs.putOverwrite("OriginalMessage", originalMessage);
        sfs.putOverwrite("Description", e.toString());
        return sfs;
    }
  
}
