import clsx from 'clsx';
import Heading from '@theme/Heading';
import styles from './styles.module.css';

const FeatureList = [
  {
    title: 'Constrain',
    description: (
      <>
        Define what AI agents can do with signed <code>.aflock</code> policy files.
        Set spend limits, tool restrictions, file access patterns, and domain allowlists.
      </>
    ),
  },
  {
    title: 'Attest',
    description: (
      <>
        Every agent action produces a cryptographically signed in-toto attestation.
        The agent never sees the signing key — unforgeable proof of compliance.
      </>
    ),
  },
  {
    title: 'Verify',
    description: (
      <>
        Verify constraint compliance after the fact with a 6-phase verification algorithm.
        Cross-step Rego evaluation, merkle tree ordering proofs, and sublayout recursion.
      </>
    ),
  },
];

function Feature({title, description}) {
  return (
    <div className={clsx('col col--4')}>
      <div className="text--center padding-horiz--md" style={{paddingTop: '2rem'}}>
        <Heading as="h3">{title}</Heading>
        <p>{description}</p>
      </div>
    </div>
  );
}

export default function HomepageFeatures() {
  return (
    <section className={styles.features}>
      <div className="container">
        <div className="row">
          {FeatureList.map((props, idx) => (
            <Feature key={idx} {...props} />
          ))}
        </div>
      </div>
    </section>
  );
}
