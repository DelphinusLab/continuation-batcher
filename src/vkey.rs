use ff::PrimeField;
use num_traits::ToBytes;
use halo2_proofs::arithmetic::{MultiMillerLoop, FieldExt};
use halo2_proofs::plonk::Circuit;
use halo2_proofs::plonk::{Gate, Column, Advice, Fixed, Instance, Any, ConstraintSystem, ColumnType, Expression};
use halo2_proofs::poly::Rotation;
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::EvaluationDomain;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::plonk::keygen_vk;
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::plonk::permutation;
use halo2_proofs::helpers::CurveRead;
use std::io;
use std::path::Path;
use halo2_proofs::plonk;
use num_derive::FromPrimitive;
use num;

pub fn load_or_build_unsafe_params<E: MultiMillerLoop>(
    k: u32,
    cache_file_opt: Option<&Path>,
) -> Params<E::G1Affine> {
    if let Some(cache_file) = &cache_file_opt {
        if Path::exists(&cache_file) {
            println!("read params K={} from {:?}", k, cache_file);
            let mut fd = std::fs::File::open(&cache_file).unwrap();
            return Params::<E::G1Affine>::read(&mut fd).unwrap();
        }
    }

    let params = Params::<E::G1Affine>::unsafe_setup::<E>(k);

    if let Some(cache_file) = &cache_file_opt {
        println!("write params K={} to {:?}", k, cache_file);
        let mut fd = std::fs::File::create(&cache_file).unwrap();
        params.write(&mut fd).unwrap();
    };

    params
}

pub fn load_vkey<E: MultiMillerLoop, C: Circuit<E::Scalar>>(
    params: &Params<E::G1Affine>,
    cache_file: &Path,
) -> VerifyingKey<E::G1Affine> {
    println!("read vkey from {:?}", cache_file);
    let mut fd = std::fs::File::open(&cache_file).unwrap();
    VerifyingKey::read::<_, C>(&mut fd, params).unwrap()
}

pub fn load_or_build_vkey<E: MultiMillerLoop, C: Circuit<E::Scalar>>(
    params: &Params<E::G1Affine>,
    circuit: &C,
    cache_file_opt: Option<&Path>,
) -> VerifyingKey<E::G1Affine> {
    if let Some(cache_file) = &cache_file_opt {
        if Path::exists(&cache_file) {
            return load_vkey::<E, C>(params, &cache_file);
        }
    }

    let verify_circuit_vk = keygen_vk(&params, circuit).expect("keygen_vk should not fail");

    if let Some(cache_file) = &cache_file_opt {
        println!("write vkey to {:?}", cache_file);
        let mut fd = std::fs::File::create(&cache_file).unwrap();
        verify_circuit_vk.write(&mut fd).unwrap();
    };

    verify_circuit_vk
}

fn write_argument<W: std::io::Write>(column: &Column<Any>, writer: &mut W) -> std::io::Result<()> {
    writer.write(&mut column.index.to_le_bytes())?;
    writer.write(&mut (*column.column_type() as u32).to_le_bytes())?;
    Ok(())
}

fn read_argument<R: std::io::Read>(reader: &mut R) -> std::io::Result<Column<Any>> {
    let index = read_u32(reader)?;
    let typ = read_u32(reader)?;
    let typ = if typ == Any::Advice as u32 { Any::Advice }
    else if typ == Any::Instance as u32 { Any::Instance }
    else if typ == Any::Fixed as u32 { Any::Instance }
    else { unreachable!() };
    Ok(Column {index: index as usize, column_type: typ})
}

fn write_arguments<W: std::io::Write>(columns: &Vec<Column<Any>>, writer: &mut W) -> std::io::Result<()> {
    writer.write(&mut (columns.len() as u32).to_le_bytes())?;
    for c in columns.iter() {
        write_argument(c, writer)?;
    }
    Ok(())
}

fn read_arguments<R: std::io::Read>(reader: &mut R) -> std::io::Result<plonk::permutation::Argument> {
    let len = read_u32(reader)?;
    let mut cols = vec![];
    for i in 0..len {
        cols.push(read_argument(reader)?);
    }
    Ok(plonk::permutation::Argument {columns: cols})
}


fn write_column<T: ColumnType, W: std::io::Write>(encode: Any, column: &Column<T>, writer: &mut W) -> std::io::Result<()> {
    writer.write(&mut column.index.to_le_bytes())?;
    writer.write(&mut (encode as u32).to_le_bytes())?;
    Ok(())
}

fn read_column<T: ColumnType, R: std::io::Read>(reader: &mut R) -> std::io::Result<Column<T>> {
    todo!();
}

fn write_queries<T: ColumnType, W: std::io::Write>(encode: Any, columns: &Vec<(Column<T>, Rotation)>, writer: &mut W) -> std::io::Result<()> {
    writer.write(&mut (columns.len() as u32).to_le_bytes())?;
    for (c, rotation) in columns.iter() {
        write_column(encode, c, writer)?;
        writer.write(&mut rotation.0.to_le_bytes())?;
    }
    Ok(())
}

fn read_queries<T: ColumnType, R: std::io::Read>(reader: &mut R) -> std::io::Result<Vec<(Column<T>, Rotation)>> {
    let mut queries = vec![];
    let len = read_u32(reader)?;
    for i in 0..len {
        let column = read_column(reader)?;
        let rotation = read_u32(reader)?;
        let rotation = Rotation (rotation as i32); //u32 to i32??
        queries.push((column, rotation))
    };
    Ok(queries)
}

fn write_fixed_column<W: std::io::Write>(column: &Column<Fixed>, writer: &mut W) -> std::io::Result<()> {
    writer.write(&mut column.index.to_le_bytes())?;
    Ok(())
}

fn read_fixed_column<R: std::io::Read>(reader: &mut R) -> std::io::Result<Column<Fixed>> {
    let index = read_u32(reader)?;
    Ok(Column::<Fixed>::new(index as usize, Fixed))
}

fn write_fixed_columns<W: std::io::Write>(columns: &Vec<Column<Fixed>>, writer: &mut W) -> std::io::Result<()> {
    writer.write(&mut (columns.len() as u32).to_le_bytes())?;
    for c in columns.iter() {
        write_fixed_column(c, writer)?;
    }
    Ok(())
}

fn read_fixed_columns<R: std::io::Read>(reader: &mut R) -> std::io::Result<Vec<Column<Fixed>>> {
    let len = read_u32(reader)?;
    let mut columns = vec![];
    for i in 0..len {
        columns.push(read_fixed_column(reader)?);
    }
    Ok(columns)
}

fn write_cs<C:CurveAffine, W: io::Write>(cs: &ConstraintSystem<C::Scalar>, writer: &mut W) -> io::Result<()> {
    writer.write(&mut cs.num_fixed_columns.to_le_bytes())?;
    writer.write(&mut cs.num_advice_columns.to_le_bytes())?;
    writer.write(&mut cs.num_instance_columns.to_le_bytes())?;
    writer.write(&mut cs.num_selectors.to_le_bytes())?;
    writer.write(&mut cs.num_fixed_columns.to_le_bytes())?;
    writer.write(&mut (cs.num_advice_queries.len() as u32).to_le_bytes())?;
    for n in cs.num_advice_queries.iter() {
        writer.write(&mut n.to_le_bytes())?;
    };
    write_fixed_columns(&cs.selector_map, writer)?;
    write_fixed_columns(&cs.constants, writer)?;
    write_queries::<Advice, W>(Any::Advice, &cs.advice_queries, writer)?;
    write_queries::<Instance, W>(Any::Instance, &cs.instance_queries, writer)?;
    write_queries::<Fixed, W>(Any::Fixed, &cs.fixed_queries, writer)?;
    write_arguments(&cs.permutation.columns, writer)?;
    writer.write(&cs.lookups.len().to_le_bytes())?;
    for p in cs.lookups.iter() {
        write_expressions::<C, W>(&p.input_expressions, writer)?;
        write_expressions::<C, W>(&p.table_expressions, writer)?;
    }
    write_gates::<C, W>(&cs.gates, writer)?;
    Ok(())
}

fn read_u32<R: io::Read>(reader: &mut R) -> io::Result<u32> {
    let mut r = [0u8;4];
    reader.read(&mut r)?;
    Ok(u32::from_le_bytes(r))
}

fn read_cs<C:CurveAffine, R: io::Read>(reader: &mut R) -> io::Result<ConstraintSystem<C::Scalar>> {
    let num_fixed_columns = read_u32(reader)? as usize;
    let num_advice_columns = read_u32(reader)? as usize;
    let num_instance_columns = read_u32(reader)? as usize;
    let num_selectors = read_u32(reader)? as usize;
    let num_fixed_columns = read_u32(reader)? as usize;

    let num_advice_queries_len = read_u32(reader)?;
    let mut num_advice_queries = vec![];
    for _ in 0..num_advice_queries_len {
        num_advice_queries.push(read_u32(reader)? as usize);
    };

    let selector_map = read_fixed_columns(reader)?;
    let constants = read_fixed_columns(reader)?;

    let advice_queries = read_queries::<Advice, R>(reader)?;
    let instance_queries = read_queries::<Instance, R>(reader)?;
    let fixed_queries = read_queries::<Fixed, R>(reader)?;

    let permutation = read_arguments(reader)?;
    let mut lookups = vec![];
    let mut nb_lookup = read_u32(reader)?;
    for _ in 0..nb_lookup {
        let input_expressions = read_expressions::<C, R>(reader)?;
        let table_expressions = read_expressions::<C, R>(reader)?;
        lookups.push(plonk::lookup::Argument {
            name: "",
            input_expressions,
            table_expressions,
        });
    }
    let gates = read_gates::<C, R>(reader)?;
    Ok(ConstraintSystem{
        num_fixed_columns,
        num_advice_columns,
        num_instance_columns,
        num_selectors,
        selector_map,
        gates,
        advice_queries,
        num_advice_queries,
        instance_queries,
        fixed_queries,
        permutation,
        lookups,
        constants,
        minimum_degree: None,
    })
}



fn write_expressions<C:CurveAffine, W: std::io::Write>(expressions: &Vec<Expression<C::Scalar>>, writer: &mut W) -> std::io::Result<()> {
    writer.write(&mut (expressions.len() as u32).to_le_bytes())?;
    for e in expressions.iter() {
        encode_expression(&e, writer)?;
    }
    Ok(())
}

fn read_expressions<C:CurveAffine, R: std::io::Read>(reader: &mut R) -> std::io::Result<Vec<Expression<C::Scalar>>> {
    let nb_expr = read_u32(reader)?;
    let mut exps = vec![];
    for _ in 0..nb_expr {
        exps.push(decode_expression(reader)?)
    }
    Ok(exps)
}

fn write_gates<C:CurveAffine, W: std::io::Write>(gates: &Vec<Gate<C::Scalar>>, writer: &mut W) -> std::io::Result<()> {
    writer.write(&mut (gates.len() as u32).to_le_bytes())?;
    for gate in gates.iter() {
        write_expressions::<C, W>(&gate.polys, writer)?;
    }
    Ok(())
}

fn read_gates<C:CurveAffine, R: std::io::Read>(reader: &mut R) -> std::io::Result<Vec<Gate<C::Scalar>>> {
    let nb_gates = read_u32(reader)?;
    let mut gates = vec![];
    for _ in 0..nb_gates {
        gates.push(Gate::default(
            read_expressions::<C, R>(reader)?
        ))
    }
    Ok(gates)
}

pub fn write_vkey<C:CurveAffine, W: io::Write>(vkey: &VerifyingKey<C>, writer: &mut W) -> io::Result<()> {
    let j = vkey.domain.get_quotient_poly_degree() + 1; // quotient_poly_degree is j-1
    let k = vkey.domain.k();
    writer.write(&mut j.to_le_bytes())?;
    writer.write(&mut k.to_le_bytes())?;
    write_cs::<C, W>(&vkey.cs, writer)?;
    vkey.write(writer)?;
    Ok(())
}

pub fn read_vkey<C:CurveAffine, R: io::Read>(
        //params: &Params<C>,
        reader: &mut R
    ) -> io::Result<VerifyingKey<C>> {
    let mut buffer = [0_u8; std::mem::size_of::<u32>()];
    reader.read_exact(&mut buffer)?;
    let j = u32::from_le_bytes(buffer);
    reader.read_exact(&mut buffer)?;
    let k = u32::from_le_bytes(buffer);
    let domain: EvaluationDomain<C::Scalar> = EvaluationDomain::new(j, k);
    let cs = read_cs::<C, R>(reader)?;

    let fixed_commitments: Vec<_> = (0..cs.num_fixed_columns)
       .map(|_| C::read(reader))
       .collect::<Result<_, _>>()?;

    let permutation = permutation::VerifyingKey::read(reader, &cs.permutation)?;

    Ok(VerifyingKey {
        domain,
        cs,
        fixed_commitments,
        permutation,
    })
}


#[derive(FromPrimitive)]
enum ExpressionCode {
    Constant = 0,
    Fixed,
    Advice,
    Instance,
    Negated,
    Sum,
    Product,
    Scaled,
}

fn expression_code<F: FieldExt>(e: &Expression<F>) -> ExpressionCode {
    match e {
        Expression::Constant(_) => ExpressionCode::Constant,
        Expression::Fixed {
            query_index:_,
            column_index:_,
            rotation:_,
        } => ExpressionCode::Fixed,
        Expression::Advice {
            query_index:_,
            column_index:_,
            rotation:_,
        } => ExpressionCode::Advice,
        Expression::Instance {
            query_index:_,
            column_index:_,
            rotation:_,
        } => ExpressionCode::Instance,
        Expression::Negated(_) => ExpressionCode::Negated,
        Expression::Sum(_, _) => ExpressionCode::Sum,
        Expression::Product(_, _) => ExpressionCode::Product,
        Expression::Scaled(_, _) => ExpressionCode::Scaled,
        Expression::Selector(selector) => unreachable!(),
    }
}

fn decode_expression<F: FieldExt, R: io::Read>(reader: &mut R) -> io::Result<Expression<F>> {
    let code = read_u32(reader)?;
    match num::FromPrimitive::from_u32(code).unwrap() {
        ExpressionCode::Constant => {
            let scalar = F::read(reader)?;
            Ok(Expression::Constant(scalar))
        },
        ExpressionCode::Fixed => {
            let query_index = read_u32(reader)? as usize;
            let column_index = read_u32(reader)? as usize;
            let rotation = Rotation (read_u32(reader)? as i32);
            Ok(Expression::Fixed {
                query_index,
                column_index,
                rotation,
            })
        },
        ExpressionCode::Advice => {
            let query_index = read_u32(reader)? as usize;
            let column_index = read_u32(reader)? as usize;
            let rotation = Rotation (read_u32(reader)? as i32);
            Ok(Expression::Advice {
                query_index,
                column_index,
                rotation,
            })
        },
        ExpressionCode::Instance => {
            let query_index = read_u32(reader)? as usize;
            let column_index = read_u32(reader)? as usize;
            let rotation = Rotation (read_u32(reader)? as i32);
            Ok(Expression::Instance {
                query_index,
                column_index,
                rotation,
            })
        },
        ExpressionCode::Negated => {
            Ok(Expression::Negated(Box::new(decode_expression(reader)?)))
        }

        ExpressionCode::Sum => {
            let a = decode_expression(reader)?;
            let b = decode_expression(reader)?;
            Ok(Expression::Sum(Box::new(a), Box::new(b)))
        }

        ExpressionCode::Product => {
            let a = decode_expression(reader)?;
            let b = decode_expression(reader)?;
            Ok(Expression::Product(Box::new(a), Box::new(b)))
        }

        ExpressionCode::Scaled => {
            let a = decode_expression(reader)?;
            let f = F::read(reader)?;
            Ok(Expression::Scaled(Box::new(a), f))
        }
    }
}

fn encode_expression<F: FieldExt, W: io::Write>(e: &Expression<F>, writer: &mut W) -> io::Result<()> {
    writer.write(&mut (expression_code(e) as u32).to_le_bytes())?;
    match e {
        Expression::Constant(scalar) => {
            writer.write(&mut scalar.to_repr().as_ref())?;
            Ok(())
        },
        Expression::Fixed {
            query_index,
            column_index,
            rotation,
        } => {
            writer.write(&query_index.to_le_bytes())?;
            writer.write(&column_index.to_le_bytes())?;
            writer.write(&mut (rotation.0).to_le_bytes())?;
            Ok(())
        },
        Expression::Advice {
            query_index,
            column_index,
            rotation,
        } => {
            writer.write(&query_index.to_le_bytes())?;
            writer.write(&column_index.to_le_bytes())?;
            writer.write(&rotation.0.to_le_bytes())?;
            Ok(())
        },
        Expression::Instance {
            query_index,
            column_index,
            rotation,
        } => {
            writer.write(&query_index.to_le_bytes())?;
            writer.write(&column_index.to_le_bytes())?;
            writer.write(&rotation.0.to_le_bytes())?;
            Ok(())
        },
        Expression::Negated(a) => encode_expression(&a, writer),
        Expression::Sum(a, b) => {
            encode_expression(&a, writer)?;
            encode_expression(&b, writer)?;
            Ok(())
        },
        Expression::Product(a, b) => {
            encode_expression(&a, writer)?;
            encode_expression(&b, writer)?;
            Ok(())
        },
        Expression::Scaled(a, f) => {
            encode_expression(&a, writer)?;
            writer.write(&mut f.to_repr().as_ref())?;
            Ok(())
        },

        Expression::Selector(_) => unreachable!(),
    }
}
